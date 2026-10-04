"""Auth Depends: текущий пользователь и проверка ролей."""
from fastapi import Depends, HTTPException, Request


def get_current_user(request: Request) -> dict:
    user = getattr(request.state, "user", None)
    role = getattr(request.state, "role", None)
    if user is None:
        raise HTTPException(401, "unauthorized")
    return {"user": user, "role": role or "admin"}


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "forbidden: требуются права admin")
    return user


def require_viewer_or_admin(user: dict = Depends(get_current_user)) -> dict:
    return user
