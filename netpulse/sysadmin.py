"""Evidence-based summaries. Event availability is an estimate, not a contractual SLA."""
from datetime import datetime


def availability(events, start, end):
    transitions=[]
    for event in events:
        try:
            at=datetime.fromisoformat(str(event['timestamp']).replace('Z','+00:00')).timestamp()
        except (ValueError, TypeError, KeyError, OSError, OverflowError):
            continue
        kind=event.get('kind')
        if kind in ('ONLINE','WATCH_ONLINE','OFFLINE','WATCH_OFFLINE') and at<=end:
            transitions.append((at,kind in ('ONLINE','WATCH_ONLINE')))
    transitions.sort(key=lambda item:item[0])
    cursor=start; state=None; up=down=0.0
    for at,new_state in transitions+[(end,None)]:
        if at<start:
            state=new_state; continue
        if state is not None:
            duration=max(0,at-cursor)
            if state: up+=duration
            else: down+=duration
        cursor=at; state=new_state
    known=up+down; window=max(end-start,1)
    observed=round(100*up/known,3) if known else None
    coverage=min(100,round(100*known/window,2))
    return dict(sla_pct=observed if coverage>=95 else None,observed_pct=observed,
                coverage_pct=coverage,up_seconds=round(up),down_seconds=round(down),
                unknown_seconds=round(max(0,window-known)),basis='event_transitions_estimate')


def ram_trend(points):
    values=[]
    for stamp,value in points:
        try:
            stamp=float(stamp); value=float(value)
            if not (0<=value<=100): continue
        except (ValueError,TypeError): continue
        values.append((stamp,value))
    values.sort()
    if len(values)<3 or values[-1][0]-values[0][0]<30:
        return dict(ok=False,n_points=len(values),note='Недостаточно истории: нужны 3+ измерения за 30+ секунд')
    first=values[0][0]; xs=[t-first for t,v in values]; ys=[v for t,v in values]
    mx=sum(xs)/len(xs); my=sum(ys)/len(ys)
    denom=sum((x-mx)**2 for x in xs)
    slope=sum((x-mx)*(y-my) for x,y in zip(xs,ys))/denom if denom else 0
    span=xs[-1]
    seconds=max(0,(95-ys[-1])/slope) if slope>1e-6 else None
    # Short samples do not justify extrapolation weeks into the future.
    horizon=min(86400,span*5)
    return dict(ok=True,last_pct=ys[-1],slope_pct_pt=round(slope*60,4),n_points=len(values),
                span_seconds=round(span),horizon_seconds=round(horizon),
                seconds_to_95=round(seconds) if seconds is not None and seconds<=horizon else None,
                days_left=None,note='Линейный тренд по времени; прогноз ограничен пятью окнами наблюдения')
