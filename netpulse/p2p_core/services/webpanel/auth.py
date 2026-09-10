# services/webpanel/auth.py — авторизация для Streamlit панели
# Не ломает основную функциональность: если auth.enabled=false — guard прозрачен.
# Хранение: config.yaml -> webpanel.auth.users {login: sha256(password)}
# Streamlit subprocess читает config напрямую (без RPC), т.к. файл доступен по P2P_PROJECT_ROOT.

import hashlib
import hmac
import os
from pathlib import Path

import yaml

# ------------------------------------------------------------------ #
#  Helpers — пути и загрузка конфига (без зависимости от ConfigManager,
#  чтобы не тянуть pydantic в streamlit subprocess лишний раз)
# ------------------------------------------------------------------ #

def _project_root() -> Path:
    # В frozen-сборке __file__ указывает в _MEIPASS (temp), а не в каталог exe.
    # Корректный корень — каталог exe (как в main.py: BASE_DIR).
    import sys
    env_root = os.environ.get("P2P_PROJECT_ROOT", "").strip()
    if env_root:
        return Path(env_root)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent.parent.parent

def _config_path() -> Path:
    # 1) явный путь к файлу — приоритет
    env_cfg = os.environ.get("P2P_CONFIG_PATH", "").strip()
    if env_cfg:
        return Path(env_cfg)
    # 2) P2P_PROJECT_ROOT/config.yaml — пробрасывается из service.py
    env_root = os.environ.get("P2P_PROJECT_ROOT", "").strip()
    if env_root:
        p = Path(env_root) / "config.yaml"
        # возвращаем даже если файла нет — покажет корректный путь в UI
        # но если файл не найден, попробуем fallback на exe-директорию
        if p.exists():
            return p
    # 3) frozen exe директория (WebUI_P2P_Core.exe рядом с config.yaml)
    import sys
    if getattr(sys, "frozen", False):
        p = Path(sys.executable).parent / "config.yaml"
        if p.exists():
            return p
        # если рядом нет — вернем его как ожидаемый путь для подсказки
        return p
    # 4) dev-режим — корень проекта
    return _project_root() / "config.yaml"

def _find_existing_config() -> Path | None:
    """Ищет существующий config.yaml по всем кандидатам, иначе None."""
    candidates: list[Path] = []
    env_cfg = os.environ.get("P2P_CONFIG_PATH", "").strip()
    if env_cfg:
        candidates.append(Path(env_cfg))
    env_root = os.environ.get("P2P_PROJECT_ROOT", "").strip()
    if env_root:
        candidates.append(Path(env_root) / "config.yaml")
    import sys
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).parent / "config.yaml")
    candidates.append(Path(__file__).parent.parent.parent / "config.yaml")
    # дедуп
    seen = set()
    uniq: list[Path] = []
    for p in candidates:
        rp = str(p.resolve()) if p.exists() else str(p)
        if rp not in seen:
            uniq.append(p)
            seen.add(rp)
    for p in uniq:
        if p.exists():
            return p
    return None

def _load_raw_config() -> dict:
    # пробуем найти реально существующий файл, иначе показываем диагностику
    existing = _find_existing_config()
    path = existing if existing is not None else _config_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

def _get_auth_section() -> dict:
    raw = _load_raw_config()
    return (raw.get("webpanel") or {}).get("auth") or {}

# ------------------------------------------------------------------ #
#  Public API
# ------------------------------------------------------------------ #

def hash_password(password: str) -> str:
    """sha256 хеш пароля — совместим с Config.users."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def is_auth_enabled() -> bool:
    """Включена ли авторизация. По умолчанию False -> панель открыта."""
    auth = _get_auth_section()
    # поддержать env-переопределение для тестов / docker
    if os.environ.get("P2P_PANEL_AUTH_ENABLED", "").lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("P2P_PANEL_AUTH_ENABLED", "").lower() in ("0", "false", "no"):
        return False
    return bool(auth.get("enabled", False))

def get_users() -> dict[str, str]:
    """Словарь login -> пароль-хеш. Подмешивает env если задан."""
    auth = _get_auth_section()
    users: dict[str, str] = dict(auth.get("users") or {})

    # env-override: P2P_PANEL_USERS="admin:hash,user:hash" или P2P_PANEL_USER / P2P_PANEL_PASSWORD_HASH
    env_users = os.environ.get("P2P_PANEL_USERS", "")
    if env_users:
        for pair in env_users.split(","):
            if ":" in pair:
                login, pwd_hash = pair.split(":", 1)
                login = login.strip()
                pwd_hash = pwd_hash.strip()
                if login and pwd_hash:
                    users[login] = pwd_hash

    env_login = os.environ.get("P2P_PANEL_USER", "").strip()
    env_hash = os.environ.get("P2P_PANEL_PASSWORD_HASH", "").strip()
    env_pwd = os.environ.get("P2P_PANEL_PASSWORD", "").strip()
    if env_login and (env_hash or env_pwd):
        users[env_login] = env_hash if env_hash else hash_password(env_pwd)

    return users

def verify_user(username: str, password: str) -> bool:
    users = get_users()
    expected = users.get(username)
    if not expected:
        return False
    actual = hash_password(password)
    # constant-time сравнение
    return hmac.compare_digest(expected, actual)

# ------------------------------------------------------------------ #
#  Streamlit helpers — вызываются из streamlit_app.py
# ------------------------------------------------------------------ #

def check_authentication() -> bool:
    """True если пользователь уже аутентифицирован в session_state."""
    try:
        import streamlit as st
        return bool(st.session_state.get("_auth_authenticated", False))
    except Exception:
        return False

def logout():
    """Сброс auth-состояния (rpc и навигация сохраняются только если нужно)."""
    try:
        import streamlit as st
        for key in ("_auth_authenticated", "_auth_user", "_auth_error"):
            st.session_state.pop(key, None)
        # не трогаем rpc / current_page / selected_node — но при желании можно очистить
    except Exception:
        pass

def render_login_page():
    """Рендер формы логина. Вызывается до всего остального + st.stop()."""
    import streamlit as st

    # центрированная форма
    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("### 🔒 Вход в P2P Panel")
        st.caption("Авторизация включена в `config.yaml → webpanel.auth`")

        # показать подсказку если пользователей нет
        users = get_users()
        if not users:
            st.warning(
                "Список пользователей пуст. Добавьте в `config.yaml`:\n\n"
                "```yaml\nwebpanel:\n  auth:\n    enabled: true\n    users:\n"
                "      admin: <sha256>\n```\n"
                f"Хеш для пароля можно получить: `python -c \"import hashlib; print(hashlib.sha256(b'YOUR_PASSWORD').hexdigest())\"`"
            )

        with st.form("webpanel_login", clear_on_submit=False):
            username = st.text_input("Логин", key="_auth_login_input")
            password = st.text_input("Пароль", type="password", key="_auth_pwd_input")
            submitted = st.form_submit_button("Войти", use_container_width=True, type="primary")

            if submitted:
                if verify_user(username.strip(), password):
                    st.session_state["_auth_authenticated"] = True
                    st.session_state["_auth_user"] = username.strip()
                    st.session_state.pop("_auth_error", None)
                    st.success(f"Добро пожаловать, {username.strip()}!")
                    st.rerun()
                else:
                    st.session_state["_auth_error"] = True
                    st.error("Неверный логин или пароль")

        if st.session_state.get("_auth_error"):
            st.caption("Подсказка: проверьте `config.yaml → webpanel.auth.users`")

        st.divider()
        cfg_path = _find_existing_config() or _config_path()
        exists = "✅" if cfg_path.exists() else "❌ не найден"
        st.caption(f"Конфиг: `{cfg_path}` {exists} · Узел: `{os.environ.get('P2P_NODE_ID','?')}`")
        if not cfg_path.exists():
            with st.expander("Диагностика путей"):
                st.code(f"P2P_CONFIG_PATH={os.environ.get('P2P_CONFIG_PATH','')}\nP2P_PROJECT_ROOT={os.environ.get('P2P_PROJECT_ROOT','')}\nsys.frozen={getattr(__import__('sys'), 'frozen', False)}\nsys.executable={__import__('sys').executable}\n__file__={__file__}")
