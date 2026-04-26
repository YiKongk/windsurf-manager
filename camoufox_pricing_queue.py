#!/usr/bin/env python3
"""Open Windsurf pricing in Camoufox for multiple saved accounts, one by one."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from windsurf_session import (
    build_init_script,
    load_session,
    normalize_session_payload,
    persist_normalized_session,
)


DEFAULT_URL = "https://windsurf.com/pricing"
DEFAULT_ACCOUNTS_ROOT = Path("auth_output")
DEFAULT_PROFILE_ROOT = Path(".camoufox-pricing-queue")
OPENED_MARKER_NAME = ".pricing_opened.json"


def prompt_text(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print(f"{prompt} is required.")


def find_session_files(accounts_root: Path) -> list[Path]:
    files = sorted(accounts_root.glob("*/windsurf_auth_session.json"))
    if not files and (accounts_root / "windsurf_auth_session.json").exists():
        files = [accounts_root / "windsurf_auth_session.json"]
    return files


def marker_path_for_session(session_path: Path) -> Path:
    return session_path.with_name(OPENED_MARKER_NAME)


def is_already_opened(session_path: Path) -> bool:
    return marker_path_for_session(session_path).exists()


def mark_as_opened(session_path: Path, email: str, url: str) -> None:
    marker_path_for_session(session_path).write_text(
        json.dumps(
            {
                "email": email,
                "url": url,
                "opened_at": datetime.now().isoformat(),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value)


def resolve_runtime_args(args: argparse.Namespace) -> argparse.Namespace:
    accounts_root = args.accounts_root or Path(prompt_text("Accounts root", str(DEFAULT_ACCOUNTS_ROOT)))
    url = args.url or prompt_text("Target URL", DEFAULT_URL)
    profile_root = args.profile_root or Path(prompt_text("Camoufox profile root", str(DEFAULT_PROFILE_ROOT)))

    return argparse.Namespace(
        accounts_root=accounts_root.resolve(),
        url=url,
        profile_root=profile_root.resolve(),
        non_interactive=args.non_interactive,
    )


def run(args: argparse.Namespace) -> int:
    args = resolve_runtime_args(args)
    session_files = find_session_files(args.accounts_root)
    if not session_files:
        raise SystemExit(f"No session files found under {args.accounts_root}")

    try:
        from camoufox.sync_api import Camoufox
    except ImportError as exc:
        raise SystemExit(
            "Camoufox is not installed. Install it with `pip install -U camoufox[geoip]` "
            "and fetch the browser with `python -m camoufox fetch`."
        ) from exc

    for index, session_path in enumerate(session_files, start=1):
        if is_already_opened(session_path):
            print(
                f"[{index}/{len(session_files)}] Skipping previously opened account: {session_path.parent.name}",
                file=sys.stderr,
            )
            continue

        raw_session_payload = load_session(session_path)
        before = json.dumps(raw_session_payload, sort_keys=True, ensure_ascii=False)
        session_payload = normalize_session_payload(raw_session_payload)
        after = json.dumps(session_payload, sort_keys=True, ensure_ascii=False)
        if before != after:
            persist_normalized_session(session_path, session_payload)
            print(f"Normalized session artifacts at {session_path}", file=sys.stderr)

        email = session_payload.get("email") or session_path.parent.name
        profile_dir = args.profile_root / sanitize_name(email)
        extra_http_headers = session_payload["playwright"]["extra_http_headers"]
        init_script = build_init_script(session_payload)

        print(
            f"[{index}/{len(session_files)}] Opened {email} in Camoufox. "
            "Handle Cloudflare and any checkout steps manually. "
            "Close the browser window to continue to the next account.",
            file=sys.stderr,
        )

        with Camoufox(
            headless=False,
            os="windows",
            humanize=True,
            persistent_context=True,
            user_data_dir=str(profile_dir),
        ) as context:
            context.set_extra_http_headers(extra_http_headers)
            context.add_init_script(init_script)

            page = context.pages[0] if context.pages else context.new_page()
            page.goto(args.url, wait_until="domcontentloaded")
            mark_as_opened(session_path, email=email, url=args.url)

            try:
                while True:
                    if page.is_closed():
                        break
                    page.wait_for_timeout(1000)
            except Exception:
                pass

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts-root", type=Path, help="Directory containing per-account auth folders")
    parser.add_argument("--url", help="Page to open for each account")
    parser.add_argument("--profile-root", type=Path, help="Root directory for per-account Camoufox profiles")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Use only command-line arguments without terminal prompts",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
