"""API Key Rotation and Rate Limit Manager for Slothery."""

import json
import os
import time
import threading
from typing import Dict, List, Optional, Tuple
from core.config import (
    KEYS_FILE,
    VT_MINUTE_WINDOW_SECONDS,
    RATE_LIMIT_COOLDOWN_SECONDS,
)

# Status constants
STATUS_ACTIVE = "ACTIVE"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_EXHAUSTED = "EXHAUSTED"
STATUS_INVALID = "INVALID"

SERVICE_VT = "virustotal"
SERVICE_ABUSE = "abuseipdb"


def mask_key(key: str) -> str:
    """Masks an API key for safe UI display (e.g., abcd...1234)."""
    if not key:
        return ""
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"


class KeyEntry:
    def __init__(
        self,
        key: str,
        service: str,
        status: str = STATUS_ACTIVE,
        total_queries: int = 0,
        errors: int = 0,
        cooldown_until: float = 0.0,
        error_message: str = "",
    ):
        self.key = key.strip()
        self.service = service.lower()
        self.status = status
        self.total_queries = total_queries
        self.errors = errors
        self.cooldown_until = cooldown_until
        self.error_message = error_message
        self.last_used: float = 0.0

    def is_available(self, current_time: float) -> bool:
        """Returns True if the key is ready for a new request."""
        if self.status in (STATUS_EXHAUSTED, STATUS_INVALID):
            return False
        if self.status == STATUS_RATE_LIMITED:
            if current_time >= self.cooldown_until:
                self.status = STATUS_ACTIVE
                self.cooldown_until = 0.0
                return True
            return False
        return True

    def get_remaining_cooldown(self, current_time: float) -> float:
        """Returns seconds remaining in cooldown, or 0.0 if ready."""
        if self.status == STATUS_RATE_LIMITED and self.cooldown_until > current_time:
            return self.cooldown_until - current_time
        return 0.0

    def to_dict(self) -> Dict:
        return {
            "key": self.key,
            "service": self.service,
            "status": self.status,
            "total_queries": self.total_queries,
            "errors": self.errors,
            "cooldown_until": self.cooldown_until,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "KeyEntry":
        return cls(
            key=data.get("key", ""),
            service=data.get("service", ""),
            status=data.get("status", STATUS_ACTIVE),
            total_queries=data.get("total_queries", 0),
            errors=data.get("errors", 0),
            cooldown_until=data.get("cooldown_until", 0.0),
            error_message=data.get("error_message", ""),
        )


class KeyManager:
    """Thread-safe manager for API key rotation pools."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(KeyManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.pools: Dict[str, List[KeyEntry]] = {
            SERVICE_VT: [],
            SERVICE_ABUSE: [],
        }
        self.indices: Dict[str, int] = {
            SERVICE_VT: 0,
            SERVICE_ABUSE: 0,
        }
        self.data_lock = threading.Lock()
        self._load_keys()
        self._initialized = True

    def _load_keys(self):
        """Loads keys from keys.json and .env."""
        with self.data_lock:
            # 1. Load from keys.json if exists
            if KEYS_FILE.exists():
                try:
                    with open(KEYS_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data.get("keys", []):
                            entry = KeyEntry.from_dict(item)
                            if entry.service in self.pools:
                                # avoid duplicate
                                if not any(k.key == entry.key for k in self.pools[entry.service]):
                                    self.pools[entry.service].append(entry)
                except Exception as e:
                    print(f"Warning: Failed to load keys from {KEYS_FILE}: {e}")

            # 2. Ingest from environment variables (.env)
            vt_env = os.getenv("VIRUSTOTAL_API_KEYS", "") or os.getenv("VIRUSTOTAL_API_KEY", "")
            if vt_env:
                for k in vt_env.split(","):
                    k = k.strip()
                    if k and not any(entry.key == k for entry in self.pools[SERVICE_VT]):
                        self.pools[SERVICE_VT].append(KeyEntry(key=k, service=SERVICE_VT))

            abuse_env = os.getenv("ABUSEIPDB_API_KEYS", "") or os.getenv("ABUSEIPDB_API_KEY", "")
            if abuse_env:
                for k in abuse_env.split(","):
                    k = k.strip()
                    if k and not any(entry.key == k for entry in self.pools[SERVICE_ABUSE]):
                        self.pools[SERVICE_ABUSE].append(KeyEntry(key=k, service=SERVICE_ABUSE))

    def _save_keys(self):
        """Persists current key configurations to keys.json."""
        data = {
            "keys": [
                entry.to_dict()
                for pool in self.pools.values()
                for entry in pool
            ]
        }
        try:
            with open(KEYS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save keys to {KEYS_FILE}: {e}")

    def add_key(self, service: str, key: str) -> Tuple[bool, str]:
        """Adds a new key to the specified service pool."""
        service = service.lower()
        key = key.strip()
        if not key:
            return False, "API key cannot be empty."
        if service not in self.pools:
            return False, f"Unknown service: {service}"

        with self.data_lock:
            if any(k.key == key for k in self.pools[service]):
                return False, "This API key is already in the pool."

            self.pools[service].append(KeyEntry(key=key, service=service))
            self._save_keys()
            return True, "Key successfully added to the pool."

    def remove_key(self, service: str, key: str) -> bool:
        """Removes a key from the pool."""
        service = service.lower()
        with self.data_lock:
            if service in self.pools:
                initial_len = len(self.pools[service])
                self.pools[service] = [k for k in self.pools[service] if k.key != key]
                if len(self.pools[service]) < initial_len:
                    self._save_keys()
                    return True
        return False

    def reset_key_status(self, service: str, key: str) -> bool:
        """Resets a key's status back to ACTIVE."""
        service = service.lower()
        with self.data_lock:
            for entry in self.pools.get(service, []):
                if entry.key == key:
                    entry.status = STATUS_ACTIVE
                    entry.cooldown_until = 0.0
                    entry.error_message = ""
                    self._save_keys()
                    return True
        return False

    def get_next_key(self, service: str) -> Tuple[Optional[str], Optional[float]]:
        """
        Retrieves the next available API key using round-robin rotation.
        Returns:
            (key, 0.0) -> Ready key found.
            (None, wait_seconds) -> All available keys are in cooldown; wait_seconds is time to earliest reset.
            (None, None) -> No keys registered or all keys are permanently EXHAUSTED / INVALID.
        """
        service = service.lower()
        now = time.time()

        with self.data_lock:
            pool = self.pools.get(service, [])
            if not pool:
                return None, None

            total = len(pool)
            start_idx = self.indices[service] % total

            # 1. Round-robin search for an ACTIVE / ready key
            for i in range(total):
                idx = (start_idx + i) % total
                entry = pool[idx]
                if entry.is_available(now):
                    self.indices[service] = (idx + 1) % total
                    entry.last_used = now
                    return entry.key, 0.0

            # 2. If none ready, check if any are in temporary cooldown
            min_cooldown = float("inf")
            has_throttled_keys = False

            for entry in pool:
                if entry.status == STATUS_RATE_LIMITED:
                    rem = entry.get_remaining_cooldown(now)
                    if rem > 0:
                        has_throttled_keys = True
                        if rem < min_cooldown:
                            min_cooldown = rem

            if has_throttled_keys and min_cooldown != float("inf"):
                # Return minimum seconds needed to wait
                return None, max(1.0, min_cooldown)

            # All keys are permanently EXHAUSTED or INVALID
            return None, None

    def mark_success(self, service: str, key: str):
        """Increment success counter for key."""
        service = service.lower()
        with self.data_lock:
            for entry in self.pools.get(service, []):
                if entry.key == key:
                    entry.total_queries += 1
                    entry.status = STATUS_ACTIVE
                    self._save_keys()
                    break

    def mark_rate_limited(
        self,
        service: str,
        key: str,
        cooldown_seconds: float = RATE_LIMIT_COOLDOWN_SECONDS,
        is_daily: bool = False,
    ):
        """Marks key as temporarily rate-limited or daily exhausted."""
        service = service.lower()
        now = time.time()
        with self.data_lock:
            for entry in self.pools.get(service, []):
                if entry.key == key:
                    entry.errors += 1
                    if is_daily:
                        entry.status = STATUS_EXHAUSTED
                        entry.error_message = "Daily quota exceeded."
                    else:
                        entry.status = STATUS_RATE_LIMITED
                        entry.cooldown_until = now + cooldown_seconds
                        entry.error_message = f"Rate limit reached. Cooldown {int(cooldown_seconds)}s."
                    self._save_keys()
                    break

    def mark_invalid(self, service: str, key: str, message: str = "Invalid API key"):
        """Marks key as permanently invalid."""
        service = service.lower()
        with self.data_lock:
            for entry in self.pools.get(service, []):
                if entry.key == key:
                    entry.status = STATUS_INVALID
                    entry.errors += 1
                    entry.error_message = message
                    self._save_keys()
                    break

    def get_service_summary(self, service: str) -> List[Dict]:
        """Returns key status info for UI rendering."""
        service = service.lower()
        now = time.time()
        with self.data_lock:
            result = []
            for entry in self.pools.get(service, []):
                # Update status if cooldown expired
                entry.is_available(now)
                rem_cooldown = entry.get_remaining_cooldown(now)
                result.append({
                    "key_masked": mask_key(entry.key),
                    "status": entry.status,
                    "total_queries": entry.total_queries,
                    "errors": entry.errors,
                    "remaining_cooldown": round(rem_cooldown, 1),
                    "error_message": entry.error_message,
                })
            return result

    def get_pool_counts(self) -> Dict[str, Dict[str, int]]:
        """Returns counts of active, rate-limited, and invalid keys per service."""
        now = time.time()
        with self.data_lock:
            counts = {}
            for s in [SERVICE_VT, SERVICE_ABUSE]:
                pool = self.pools.get(s, [])
                active = 0
                throttled = 0
                dead = 0
                for entry in pool:
                    if entry.is_available(now):
                        active += 1
                    elif entry.status == STATUS_RATE_LIMITED:
                        throttled += 1
                    else:
                        dead += 1
                counts[s] = {
                    "total": len(pool),
                    "active": active,
                    "throttled": throttled,
                    "dead": dead,
                }
            return counts
