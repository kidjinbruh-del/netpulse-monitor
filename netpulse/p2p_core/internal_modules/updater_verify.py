# src/internal_modules/updater_verify.py
# Проверка Authenticode-подписи exe через системный WinVerifyTrust.
# Перенесено из services/updater/verify.py — ядро, без зависимостей от services.

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


class _GUID(ctypes.Structure):
    _fields_ = [('Data1', wintypes.DWORD),
                ('Data2', wintypes.WORD),
                ('Data3', wintypes.WORD),
                ('Data4', ctypes.c_ubyte * 8)]


# WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [('cbStruct', wintypes.DWORD),
                ('pcwszFilePath', wintypes.LPCWSTR),
                ('hFile', wintypes.HANDLE),
                ('pgKnownSubject', ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', ctypes.c_void_p),
        ('pSIPClientData', ctypes.c_void_p),
        ('dwUIChoice', wintypes.DWORD),            # WTD_UI_NONE = 2
        ('fdwRevocationChecks', wintypes.DWORD),   # WTD_REVOKE_NONE = 0
        ('dwUnionChoice', wintypes.DWORD),         # WTD_CHOICE_FILE = 1
        ('pFile', ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ('dwStateAction', wintypes.DWORD),         # WTD_STATEACTION_IGNORE
        ('hWVTStateData', wintypes.HANDLE),
        ('pwszURLReference', wintypes.LPCWSTR),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD),
        ('pSignatureSettings', ctypes.c_void_p),
    ]


_TRUST_ERRORS = {
    0x800B0100: 'подпись не найдена (TRUST_E_NOSIGNATURE)',
    0x800B0101: 'сертификат истёк или ещё не действует',
    0x800B0109: 'сертификат не в доверенных корневых '
                '(CERT_E_UNTRUSTEDROOT — установлен ли CA на этом узле?)',
    0x800B010A: 'не удалось получить подписавшего (CRYPT_E_NO_SIGNER)',
    0x80092002: 'ошибка цепочки сертификатов',
}


def verify_signature(path) -> tuple:
    """(ok: bool, detail: str). На не-Windows — (False, причина)."""
    if os.name != 'nt':
        return False, 'WinVerifyTrust доступен только на Windows'
    p = Path(path)
    if not p.is_file():
        return False, f'файл не найден: {p}'

    file_info = _WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
        pcwszFilePath=str(p.resolve()),
        hFile=None,
        pgKnownSubject=None,
    )
    wtd = _WINTRUST_DATA(
        cbStruct=ctypes.sizeof(_WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=2,               # WTD_UI_NONE — никаких диалогов
        fdwRevocationChecks=0,      # WTD_REVOKE_NONE
        dwUnionChoice=1,            # WTD_CHOICE_FILE
        pFile=ctypes.pointer(file_info),
        dwStateAction=0,            # WTD_STATEACTION_IGNORE
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=0,
        dwUIContext=0,
        pSignatureSettings=None,
    )
    action = _GUID.from_buffer_copy(_ACTION_GENERIC_VERIFY_V2)

    try:
        wintrust = ctypes.windll.wintrust.WinVerifyTrust
        wintrust.argtypes = [wintypes.HWND,
                             ctypes.POINTER(_GUID),
                             ctypes.POINTER(_WINTRUST_DATA)]
        l_ret = wintrust(None, ctypes.byref(action), ctypes.byref(wtd))
    except Exception as e:
        return False, f'wintrust недоступен: {e}'

    code = l_ret & 0xFFFFFFFF
    if code == 0:
        return True, 'подпись действительна'
    return False, _TRUST_ERRORS.get(code, f'WinVerifyTrust = 0x{code:08X}')
