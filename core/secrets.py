"""
Шифрование секретов конфига через Windows DPAPI.

Значения секретных ключей (web_token, telegram.token, web_admins[].token)
при сохранении конфига автоматически шифруются и получают префикс "dpapi:",
при загрузке — расшифровываются. Привязка: пользователь + машина, ключей
нигде не хранится. Скопированный на другую машину config.json секреты
раскрыть не сможет.
"""

import base64
import ctypes
import sys

PREFIX = "dpapi:"

# Ключи конфига, значения которых шифруем (на любом уровне вложенности)
SECRET_KEYS = {"web_token", "token"}


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint), ("pbData", ctypes.c_void_p)]


def _crypt(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise OSError("DPAPI доступен только на Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    # точные прототипы: иначе 64-битные указатели обрезаются до int
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.c_wchar_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
        ctypes.POINTER(_DATA_BLOB)]
    crypt32.CryptProtectData.restype = ctypes.c_int
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
        ctypes.POINTER(_DATA_BLOB)]
    crypt32.CryptUnprotectData.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    buf = ctypes.create_string_buffer(data, len(data))
    din = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p))
    dout = _DATA_BLOB()
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(din), "netpulse",
                                      None, None, None, 0, ctypes.byref(dout))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(din), None,
                                        None, None, None, 0, ctypes.byref(dout))
    if not ok:
        raise OSError("ошибка DPAPI")
    out = ctypes.string_at(dout.pbData, dout.cbData)
    kernel32.LocalFree(dout.pbData)
    return out


def is_encrypted(v) -> bool:
    return isinstance(v, str) and v.startswith(PREFIX)


def encrypt_value(plain: str) -> str:
    enc = _crypt(plain.encode("utf-8"), protect=True)
    return PREFIX + base64.b64encode(enc).decode("ascii")


def decrypt_value(stored: str) -> str:
    raw = base64.b64decode(stored[len(PREFIX):])
    return _crypt(raw, protect=False).decode("utf-8")


def _encrypt_if_secret(key, value):
    if (key in SECRET_KEYS and isinstance(value, str)
            and value and not is_encrypted(value)):
        try:
            return encrypt_value(value)
        except Exception:
            return value
    return value


def encrypt_config(node, key=None):
    """Рекурсивно шифрует секретные строковые значения (для save_config)."""
    if isinstance(node, dict):
        return {k: encrypt_config(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [encrypt_config(x, key) for x in node]
    return _encrypt_if_secret(key, node)


def decrypt_config(node, key=None):
    """Рекурсивно расшифровывает значения с префиксом dpapi: (для load_config).
    При сбое (другая машина/профиль) оставляет значение как есть."""
    if isinstance(node, dict):
        return {k: decrypt_config(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [decrypt_config(x, key) for x in node]
    if is_encrypted(node):
        try:
            return decrypt_value(node)
        except Exception:
            return node
    return node
