#!/usr/bin/env python3
"""Shared Windsurf session helpers for browser automation scripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

WINDSURF_ORIGIN = "https://windsurf.com"

DEVIN_SESSION_TOKEN_KEY = "devin_session_token"
DEVIN_AUTH1_TOKEN_KEY = "devin_auth1_token"
DEVIN_ACCOUNT_ID_KEY = "devin_account_id"
DEVIN_PRIMARY_ORG_ID_KEY = "devin_primary_org_id"


def load_session(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def find_default_session_path() -> Path:
    direct_path = Path("auth_output/windsurf_auth_session.json")
    candidates: list[Path] = []
    if direct_path.exists():
        candidates.append(direct_path)
    candidates.extend(Path("auth_output").glob("*/windsurf_auth_session.json"))
    if not candidates:
        return direct_path
    return max(candidates, key=lambda path: path.stat().st_mtime)


def prompt_text(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print(f"{prompt} is required.")


def ensure_json_scalar_string(value: str) -> str:
    try:
        decoded = json.loads(value)
        if isinstance(decoded, (str, int, float, bool)) or decoded is None:
            return value
    except Exception:
        pass
    return json.dumps(value)


def normalize_session_payload(session_payload: dict[str, Any]) -> dict[str, Any]:
    playwright_payload = session_payload.setdefault("playwright", {})
    storage_state = playwright_payload.setdefault("storage_state", {"cookies": [], "origins": []})
    origins = storage_state.setdefault("origins", [])
    if not origins:
        origins.append({"origin": WINDSURF_ORIGIN, "localStorage": []})

    local_storage_entries = list(playwright_payload.get("local_storage_entries") or [])
    if not local_storage_entries:
        local_storage_entries = list(origins[0].get("localStorage") or [])

    key_map = {
        "windsurf.devin_session_token": DEVIN_SESSION_TOKEN_KEY,
        "windsurf.auth1_token": DEVIN_AUTH1_TOKEN_KEY,
        "windsurf.account_id": DEVIN_ACCOUNT_ID_KEY,
        "windsurf.primary_org_id": DEVIN_PRIMARY_ORG_ID_KEY,
    }
    devin_keys = {
        DEVIN_SESSION_TOKEN_KEY,
        DEVIN_AUTH1_TOKEN_KEY,
        DEVIN_ACCOUNT_ID_KEY,
        DEVIN_PRIMARY_ORG_ID_KEY,
    }

    normalized_entries = []
    seen = set()
    for entry in local_storage_entries:
        name = key_map.get(entry["name"], entry["name"])
        value = entry["value"]
        if name in devin_keys:
            value = ensure_json_scalar_string(value)
        normalized_entries.append({"name": name, "value": value})
        seen.add(name)

    headers = session_payload.get("headers", {})
    fallback_entries = [
        (DEVIN_SESSION_TOKEN_KEY, headers.get("x-devin-session-token")),
        (DEVIN_AUTH1_TOKEN_KEY, headers.get("x-devin-auth1-token")),
        (DEVIN_ACCOUNT_ID_KEY, headers.get("x-devin-account-id")),
        (DEVIN_PRIMARY_ORG_ID_KEY, headers.get("x-devin-primary-org-id")),
    ]
    for name, value in fallback_entries:
        if name not in seen and value:
            normalized_entries.append({"name": name, "value": json.dumps(value)})

    playwright_payload["local_storage_entries"] = normalized_entries
    origins[0]["origin"] = WINDSURF_ORIGIN
    origins[0]["localStorage"] = normalized_entries
    return session_payload


def persist_normalized_session(session_path: Path, session_payload: dict[str, Any]) -> None:
    save_json(session_path, session_payload)
    storage_state_path = session_path.with_name("windsurf_storage_state.json")
    save_json(storage_state_path, session_payload["playwright"]["storage_state"])


def build_init_script(session_payload: dict[str, Any]) -> str:
    auth_blob = json.dumps(
        {
            "headers": session_payload["headers"],
            "playwright": session_payload["playwright"],
            "email": session_payload["email"],
            "account_id": session_payload["account_id"],
            "primary_org_id": session_payload["primary_org_id"],
        },
        ensure_ascii=True,
    )
    return f"""
(() => {{
  const auth = {auth_blob};
  window.__WINDSURF_AUTH__ = auth;

  if (window.location.origin === \"{WINDSURF_ORIGIN}\") {{
    for (const entry of auth.playwright.local_storage_entries || []) {{
      try {{
        localStorage.setItem(entry.name, entry.value);
      }} catch (error) {{
        console.warn(\"localStorage injection failed\", entry.name, error);
      }}
    }}
  }}
}})();
"""