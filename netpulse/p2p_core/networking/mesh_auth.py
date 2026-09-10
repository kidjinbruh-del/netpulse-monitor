# GRID/src/networking/mesh_auth.py — авторизация HELLO/HELLO_ACK общим секретом.
#
# Если у ноды задан config.local.secret (config.yaml -> local.secret), все
# узлы в решётке ОБЯЗАНЫ подписывать HELLO отпечатком
#     sig = base64(hmac_sha256(secret, f"{source}\n{session_id}"))
# и нода-приёмник отклоняет HELLO без валидной подписи (HELLO_REJECT).
# Секрет None на всех узлах => mesh открытый (обратная совместимость).

import base64
import hashlib
import hmac
import os

# Поле в data HELLO с отпечатком
SIG_FIELD = 'sig'

# Поле в data HELLO, сигнализирующее что узел-отправитель одноранговый
_auth_versions = {}


def sign_hello(node_id: str, session_id: str, secret: str | None) -> str | None:
    """Вернуть отпечаток sig для HELLO, либо None (открытый доступ)."""
    if not secret:
        return None
    msg = f"{node_id}\n{session_id}".encode('utf-8')
    return base64.b64encode(
        hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest()
    ).decode('ascii')


def verify_sig(node_id: str, session_id: str, secret: str | None,
               provided: str | None) -> bool:
    """Проверить отпечаток. secret=None => доверяем всем (mesh открытый)."""
    if not secret:
        return True
    if not provided:
        return False
    expected = sign_hello(node_id, session_id, secret)
    if not expected:
        return False
    return hmac.compare_digest(expected.encode('ascii'),
                               provided.encode('ascii'))