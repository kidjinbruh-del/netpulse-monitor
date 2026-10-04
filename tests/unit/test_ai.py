"""Unit: AI (train/analyze/predict/orchestrator) — синтетика, без сети."""
import pytest

from ai.orchestrator import AIOrchestrator
from ai.predictive_agent import PredictiveAgent
from ai.synapse_agent import SynapseAgent
from ai.traffic_agent import TrafficAIAgent


def _rows(n=30, speed=100.0):
    return [{"speed": speed + (i % 5), "bytes_in": 1000 + i,
             "bytes_out": 500 + i, "ping_ms": 10 + (i % 3)}
            for i in range(n)]


def test_traffic_train_analyze():
    agent = TrafficAIAgent({"features": ["speed", "bytes_in", "ping_ms"]})
    assert agent.train(_rows(5)) is False  # мало данных
    assert agent.train(_rows(30)) is True
    assert agent.stats["model_trained"] is True
    res = agent.analyze({"speed": 100.0, "bytes_in": 1010,
                         "bytes_out": 510, "ping_ms": 11})
    assert res["is_anomaly"] is False
    assert agent.stats["total_analyzed"] == 1
    assert agent.get_anomalies() == []


def test_traffic_disabled():
    agent = TrafficAIAgent({"enabled": False})
    assert agent.train(_rows(30)) is False
    res = agent.analyze({"speed": 1.0})
    assert res == {"timestamp": res["timestamp"], "is_anomaly": False,
                   "confidence": 0.0, "score": 0.0, "features": {}}


def test_traffic_anomaly_detected():
    agent = TrafficAIAgent({"features": ["speed", "bytes_in", "ping_ms"],
                            "anomaly_threshold": 0.0})
    assert agent.train(_rows(30)) is True
    res = agent.analyze({"speed": 99999.0, "bytes_in": 99999,
                         "bytes_out": 1, "ping_ms": 999.0})
    assert res["is_anomaly"] is True
    assert len(agent.get_anomalies()) == 1


def test_predictive_flow():
    agent = PredictiveAgent()
    assert agent.predict_next("speed") == {
        "error": "Недостаточно данных для прогнозирования"}
    for i in range(25):
        agent.update({"speed": 100.0 + i})
    pred = agent.predict_next("speed")
    assert pred["metric"] == "speed"
    assert pred["trend"] > 0
    assert 0 < pred["confidence"] < 1
    assert len(agent.get_predictions()) == 1
    assert agent.get_stats()["history_size"] == 25


def test_predictive_disabled():
    agent = PredictiveAgent({"enabled": False})
    assert agent.predict_next() == {"error": "Агент отключен"}
    agent.update({"speed": 1})
    assert agent.get_stats()["history_size"] == 0


def test_synapse_sim_contract():
    agent = SynapseAgent("test", ["a"])
    assert agent.broadcast({"type": "x"}) is False  # не подключён
    assert agent.connect("wss://hub") is True
    assert agent.broadcast({"type": "ping"}) is True
    assert agent.delegate_task({"type": "job"}) is True
    st = agent.get_stats()
    assert st["connected"] is True and st["peers"] == 3
    assert st["messages_count"] == 1 and st["pending_tasks"] == 1


def test_orchestrator_wiring():
    alerts = []
    orch = AIOrchestrator(
        config={"training_interval": 300},
        alert_callback=lambda a: alerts.append(a),
        data_provider=lambda: _rows(30),
    )
    assert orch.train_model(_rows(30)) is True
    out = orch.process_traffic_data({"speed": 100.0, "bytes_in": 1000,
                                     "bytes_out": 500, "ping_ms": 10})
    assert "analysis" in out and "prediction" in out and "stats" in out
    stats = orch.get_stats()
    assert stats["traffic"]["model_trained"] is True
    assert stats["running"] is False
    assert orch.get_anomalies(5) == []
    orch.set_enabled(False)
    assert orch.traffic_agent.is_enabled is False
    orch.stop()  # не запущен — без ошибок
