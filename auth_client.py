"""
048 Auth Client - drop this file into your cheat project.

Usage:
    from auth_client import Client048

    client = Client048(
        base_url = "https://your-service.railway.app",
        api_key  = "your_internal_api_key",   # matches INTERNAL_API_KEY env var on Railway
    )

    key = input("License key: ").strip()
    client.authenticate(key)   # exits on failure, sets client.user on success

    # Log cheat events at any point:
    client.event("inject")
    client.event("menu_open")
    client.event("menu_close")
    client.event("destruct")
    client.event("fac_reset_request", note="User pressed FAC reset button")
    client.event("custom", note="anything you want to log")
"""

import hashlib
import json
import locale
import os
import platform
import socket
import sys
import urllib.request
import urllib.error
import ctypes
from typing import Optional


# ─── SYSTEM INFO COLLECTION ───────────────────────────────────────────────────

def _get_hwid() -> str:
    """
    Stable machine fingerprint. Hashes together several hardware identifiers
    so it survives reboots but changes if the user moves to a new machine.
    """
    parts = [
        str(uuid_node()),
        platform.node(),
        platform.machine(),
        platform.processor(),
    ]
    # Windows: add disk serial for extra stability
    if platform.system() == "Windows":
        try:
            import subprocess
            result = subprocess.check_output(
                ["wmic", "diskdrive", "get", "SerialNumber"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode(errors="ignore")
            serial = "".join(result.split()).replace("SerialNumber", "")
            if serial:
                parts.append(serial[:32])
        except Exception:
            pass

    raw = "|".join(p for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def uuid_node() -> int:
    import uuid
    return uuid.getnode()


def _get_system_info() -> dict:
    """Collect non-sensitive system metadata for logging."""
    info: dict = {}

    # OS
    info["os"] = f"{platform.system()} {platform.release()}"
    info["build"] = platform.version()

    # CPU
    cpu = platform.processor()
    if not cpu and platform.system() == "Windows":
        cpu = os.environ.get("PROCESSOR_IDENTIFIER", "")
    info["cpu"] = cpu[:80] if cpu else None

    # RAM (Windows only without psutil)
    if platform.system() == "Windows":
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength",                ctypes.c_ulong),
                    ("dwMemoryLoad",            ctypes.c_ulong),
                    ("ullTotalPhys",            ctypes.c_ulonglong),
                    ("ullAvailPhys",            ctypes.c_ulonglong),
                    ("ullTotalPageFile",        ctypes.c_ulonglong),
                    ("ullAvailPageFile",        ctypes.c_ulonglong),
                    ("ullTotalVirtual",         ctypes.c_ulonglong),
                    ("ullAvailVirtual",         ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            gb = round(stat.ullTotalPhys / (1024 ** 3), 1)
            info["ram"] = f"{gb} GB"
        except Exception:
            info["ram"] = None

        # Screen resolution
        try:
            user32 = ctypes.windll.user32
            w = user32.GetSystemMetrics(0)
            h = user32.GetSystemMetrics(1)
            info["screen"] = f"{w}x{h}"
        except Exception:
            info["screen"] = None
    else:
        info["ram"] = None
        info["screen"] = None

    # Locale
    try:
        lang, _ = locale.getdefaultlocale()
        info["locale"] = lang
    except Exception:
        info["locale"] = None

    # Hostname
    try:
        info["hostname"] = socket.gethostname()[:64]
    except Exception:
        info["hostname"] = None

    return {k: v for k, v in info.items() if v is not None}


def _get_public_ip() -> Optional[str]:
    """Fetch the machine's public IP via a lightweight lookup."""
    try:
        with urllib.request.urlopen("https://api4.my-ip.io/v2/ip.txt", timeout=4) as resp:
            return resp.read().decode().strip()[:64]
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=4) as resp:
            return resp.read().decode().strip()[:64]
    except Exception:
        return None


# ─── HTTP HELPER ──────────────────────────────────────────────────────────────

def _post(url: str, payload: dict, timeout: int = 8) -> dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data    = data,
        headers = {"Content-Type": "application/json"},
        method  = "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as ex:
        try:
            return json.loads(ex.read())
        except Exception:
            return {"ok": False, "error": f"http_{ex.code}"}
    except Exception as ex:
        return {"ok": False, "error": f"connection_failed: {ex}"}


# ─── CLIENT ───────────────────────────────────────────────────────────────────

_ERROR_MESSAGES = {
    "invalid_key":    "Invalid license key. Check the key and try again.",
    "banned":         "This license has been banned. Contact support.",
    "expired":        "This license has expired. Contact support to renew.",
    "hwid_mismatch":  "HWID mismatch. Contact support if you changed machines.",
    "inactive":       "This license is not active. Contact support.",
    "missing_fields": "Auth request malformed (client error).",
    "server_error":   "Server error. Try again or contact support.",
}


class Client048:
    """
    Drop-in auth + event client for 048.

    Parameters
    ----------
    base_url : str
        Your Railway service URL, e.g. "https://my-service.railway.app"
    api_key : str
        Value of the INTERNAL_API_KEY environment variable set on Railway.
        Leave blank during local dev to skip API key validation.
    exit_on_fail : bool
        If True (default), sys.exit(1) is called on auth failure so the
        cheat stops loading. Set False to handle the result yourself.
    """

    def __init__(self, base_url: str, api_key: str = "", exit_on_fail: bool = True):
        self._base    = base_url.rstrip("/")
        self._api_key = api_key
        self._exit    = exit_on_fail
        self._key     = ""
        self._hwid    = _get_hwid()
        self._ip      = _get_public_ip()
        self._system  = _get_system_info()
        self.user: Optional[dict] = None  # set after successful authenticate()

    # ------------------------------------------------------------------

    def authenticate(self, license_key: str) -> bool:
        """
        Validate license key against the server. On success, sets self.user
        and returns True. On failure, prints an error and either exits or
        returns False depending on exit_on_fail.
        """
        self._key = license_key.strip().upper()
        payload = {
            "key":     self._key,
            "hwid":    self._hwid,
            "api_key": self._api_key,
            "ip":      self._ip,
            "system":  self._system,
        }
        result = _post(f"{self._base}/auth", payload)

        if result.get("ok"):
            self.user = result
            if result.get("hwid_bound"):
                print("[AUTH] Machine registered to your license.")
            return True
        else:
            err = result.get("error", "unknown")
            msg = _ERROR_MESSAGES.get(err, f"Authentication failed: {err}")
            print(f"[AUTH] {msg}")
            if self._exit:
                sys.exit(1)
            return False

    # ------------------------------------------------------------------

    def event(self, event_type: str, note: str = "") -> bool:
        """
        Log a cheat lifecycle event.

        event_type options:
            inject            - cheat DLL/script injected
            menu_open         - overlay/menu opened by user
            menu_close        - overlay/menu closed
            destruct          - cheat shutting down / ejecting
            fac_reset_request - user triggered a FAC reset
            custom            - anything else (put detail in note)

        Returns True on success, False on network/server failure (non-fatal).
        """
        if not self._key:
            return False
        payload = {
            "key":        self._key,
            "hwid":       self._hwid,
            "api_key":    self._api_key,
            "event_type": event_type,
            "ip":         self._ip,
            "system":     self._system,
            "note":       note,
        }
        result = _post(f"{self._base}/event", payload, timeout=4)
        return bool(result.get("ok"))
