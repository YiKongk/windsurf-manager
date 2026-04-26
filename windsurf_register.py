#!/usr/bin/env python3
"""Batch-register Windsurf accounts with CloudMail inbox automation.

This script:
1. Reads CloudMail admin config and mailbox domain from `.env`
2. Prompts for how many accounts to register
3. Randomly generates email prefix, display name, and password
4. Creates the mailbox through CloudMail OpenAPI
5. Registers the Windsurf account and polls CloudMail for the verification code
6. Saves one auth bundle per email and appends credentials to a txt file
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import string
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import unescape
from http.cookiejar import Cookie
from pathlib import Path
from typing import Any

import requests


WINDSURF_BASE = "https://windsurf.com"
REGISTER_URL = f"{WINDSURF_BASE}/account/register"
CHECK_USER_LOGIN_METHOD_URL = (
    f"{WINDSURF_BASE}/_backend/"
    "exa.seat_management_pb.SeatManagementService/CheckUserLoginMethod"
)
CONNECTIONS_URL = f"{WINDSURF_BASE}/_devin-auth/connections"
EMAIL_START_URL = f"{WINDSURF_BASE}/_devin-auth/email/start"
EMAIL_COMPLETE_URL = f"{WINDSURF_BASE}/_devin-auth/email/complete"
POST_AUTH_URL = (
    f"{WINDSURF_BASE}/_backend/"
    "exa.seat_management_pb.SeatManagementService/WindsurfPostAuth"
)
GET_CURRENT_USER_URL = (
    f"{WINDSURF_BASE}/_backend/"
    "exa.seat_management_pb.SeatManagementService/GetCurrentUser"
)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/147.0.0.0 Safari/537.36"
)

DEVIN_SESSION_TOKEN_KEY = "devin_session_token"
DEVIN_AUTH1_TOKEN_KEY = "devin_auth1_token"
DEVIN_ACCOUNT_ID_KEY = "devin_account_id"
DEVIN_PRIMARY_ORG_ID_KEY = "devin_primary_org_id"

ALNUM = string.ascii_lowercase + string.digits
DEFAULT_EMAIL_PREFIX_LENGTH = 8
DEFAULT_PASSWORD_LENGTH = 12
DEFAULT_DISPLAY_NAME_LENGTH = 10
DEFAULT_MAIL_POLL_INTERVAL_SECONDS = 5
DEFAULT_MAIL_POLL_TIMEOUT_SECONDS = 180
DEFAULT_POOL_API_BASE_URL = "http://localhost:3003"
VERIFICATION_CODE_REGEXES = [
    re.compile(r"(?<!\d)(\d{6})(?!\d)"),
    re.compile(r"code[^0-9]{0,24}(\d{6})(?!\d)", re.IGNORECASE),
]
POOL_TOKEN_PATTERNS = [
    re.compile(r'"token"\s*:\s*"([^"]+)"'),
    re.compile(r"token(?:\s*[:=]\s*|\s+)([A-Za-z0-9._:$-]{20,})", re.IGNORECASE),
    re.compile(r"([A-Za-z0-9._:$-]{20,})"),
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("protobuf varint must be non-negative")
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            return bytes(out)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while True:
        if offset >= len(data):
            raise ValueError("unexpected end of protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7


def encode_len_field(field_number: int, value: str | bytes) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    key = (field_number << 3) | 2
    return write_varint(key) + write_varint(len(raw)) + raw


def encode_varint_field(field_number: int, value: int) -> bytes:
    key = field_number << 3
    return write_varint(key) + write_varint(value)


def parse_top_level_protobuf(data: bytes) -> dict[int, list[Any]]:
    offset = 0
    parsed: dict[int, list[Any]] = {}
    while offset < len(data):
        key, offset = read_varint(data, offset)
        field_number = key >> 3
        wire_type = key & 7
        if wire_type == 0:
            value, offset = read_varint(data, offset)
        elif wire_type == 2:
            size, offset = read_varint(data, offset)
            value = data[offset : offset + size]
            offset += size
        else:
            raise ValueError(f"unsupported wire type {wire_type} for field {field_number}")
        parsed.setdefault(field_number, []).append(value)
    return parsed


def decode_bytes(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def cookie_to_dict(cookie: Cookie) -> dict[str, Any]:
    return {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path,
        "secure": bool(cookie.secure),
        "httpOnly": "HttpOnly" in (cookie._rest or {}),
        "sameSite": (cookie._rest or {}).get("SameSite"),
        "expires": cookie.expires,
    }


def save_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(
            f"Missing env file: {path}. Fill it before running this script."
        )
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    merged = dict(values)
    merged.update({key: value for key, value in os.environ.items() if value})
    return merged


def read_int_setting(
    env_values: dict[str, str],
    key: str,
    default: int,
    minimum: int = 1,
) -> int:
    raw = env_values.get(key, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    return value


def prompt_text(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print(f"{prompt} is required.")


def prompt_int(prompt: str, default: int) -> int:
    while True:
        value = input(f"{prompt} [{default}]: ").strip()
        if not value:
            return default
        try:
            parsed = int(value)
        except ValueError:
            print("Please enter an integer.")
            continue
        if parsed < 1:
            print("Please enter a value >= 1.")
            continue
        return parsed


def random_alnum(length: int) -> str:
    return "".join(secrets.choice(ALNUM) for _ in range(length))


def build_playwright_data(
    cookies: list[dict[str, Any]],
    auth_headers: dict[str, str],
) -> dict[str, Any]:
    local_storage_entries = [
        {
            "name": DEVIN_SESSION_TOKEN_KEY,
            "value": json.dumps(auth_headers["x-devin-session-token"]),
        },
        {
            "name": DEVIN_AUTH1_TOKEN_KEY,
            "value": json.dumps(auth_headers["x-devin-auth1-token"]),
        },
        {
            "name": DEVIN_ACCOUNT_ID_KEY,
            "value": json.dumps(auth_headers["x-devin-account-id"]),
        },
        {
            "name": DEVIN_PRIMARY_ORG_ID_KEY,
            "value": json.dumps(auth_headers["x-devin-primary-org-id"]),
        },
    ]
    storage_state = {
        "cookies": [
            {
                "name": cookie["name"],
                "value": cookie["value"],
                "domain": cookie["domain"],
                "path": cookie["path"],
                "expires": cookie["expires"] if cookie["expires"] is not None else -1,
                "httpOnly": cookie["httpOnly"],
                "secure": cookie["secure"],
                "sameSite": cookie["sameSite"] or "Lax",
            }
            for cookie in cookies
        ],
        "origins": [
            {
                "origin": WINDSURF_BASE,
                "localStorage": local_storage_entries,
            }
        ],
    }
    return {
        "extra_http_headers": auth_headers,
        "storage_state": storage_state,
        "local_storage_entries": local_storage_entries,
    }


def strip_html(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", unescape(value or ""))


def extract_verification_code(message: dict[str, Any]) -> str | None:
    fields = [
        str(message.get("text") or ""),
        strip_html(str(message.get("content") or "")),
        str(message.get("subject") or ""),
    ]
    for field in fields:
        for pattern in VERIFICATION_CODE_REGEXES:
            match = pattern.search(field)
            if match:
                return match.group(1)
    return None


def extract_pool_token_from_text(text: str) -> str | None:
    for pattern in POOL_TOKEN_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


@dataclass
class SkyMailConfig:
    base_url: str
    admin_email: str
    admin_password: str
    domain: str
    email_prefix_length: int
    password_length: int
    display_name_length: int
    poll_interval_seconds: int
    poll_timeout_seconds: int


@dataclass
class RuntimeConfig:
    count: int
    output_dir: Path
    env_file: Path
    user_agent: str
    timeout: int
    skymail: SkyMailConfig
    pool_api_base_url: str


@dataclass
class AccountSeed:
    index: int
    email: str
    password: str
    name: str


@dataclass
class WindsurfAuthData:
    email: str
    name: str
    auth1_token: str
    devin_session_token: str
    account_id: str
    primary_org_id: str
    email_verification_token: str
    created_at: str
    current_user_response_b64: str
    cookies: list[dict[str, Any]]
    headers: dict[str, str]
    playwright: dict[str, Any]


@dataclass
class PoolImportResult:
    token: str
    response: dict[str, Any]


class SkyMailClient:
    def __init__(
        self,
        config: SkyMailConfig,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: int = 30,
    ) -> None:
        self.config = config
        self.timeout = timeout
        self.token: str | None = None
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Content-Type": "application/json",
            }
        )

    def _url(self, path: str) -> str:
        return f"{self.config.base_url.rstrip('/')}{path}"

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self.session.request(
            method=method,
            url=self._url(path),
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("code") != 200:
            raise RuntimeError(f"CloudMail API error for {path}: {data}")
        return data

    def authenticate(self) -> str:
        payload = self._request_json(
            "POST",
            "/api/public/genToken",
            payload={
                "email": self.config.admin_email,
                "password": self.config.admin_password,
            },
        )
        token = ((payload.get("data") or {}).get("token") or "").strip()
        if not token:
            raise RuntimeError(f"CloudMail genToken response missing token: {payload}")
        self.token = token
        return token

    def _auth_headers(self) -> dict[str, str]:
        if not self.token:
            self.authenticate()
        return {"Authorization": self.token or ""}

    def add_user(self, email: str, password: str) -> None:
        self._request_json(
            "POST",
            "/api/public/addUser",
            headers=self._auth_headers(),
            payload={"list": [{"email": email, "password": password}]},
        )

    def list_emails(self, to_email: str, size: int = 20) -> list[dict[str, Any]]:
        payload = self._request_json(
            "POST",
            "/api/public/emailList",
            headers=self._auth_headers(),
            payload={
                "toEmail": to_email,
                "timeSort": "desc",
                "type": 0,
                "isDel": 0,
                "num": 1,
                "size": size,
            },
        )
        return list(payload.get("data") or [])

    def wait_for_verification_code(
        self,
        to_email: str,
        timeout_seconds: int,
        interval_seconds: int,
    ) -> str:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            for message in self.list_emails(to_email=to_email):
                code = extract_verification_code(message)
                if code:
                    return code
            time.sleep(interval_seconds)
        raise TimeoutError(f"Timed out waiting for verification email for {to_email}")


class WindsurfRegistrar:
    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: int = 30,
    ) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

    def _json_headers(self) -> dict[str, str]:
        return {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": WINDSURF_BASE,
            "Referer": REGISTER_URL,
        }

    def _proto_headers(self) -> dict[str, str]:
        return {
            "Accept": "*/*",
            "Content-Type": "application/proto",
            "Origin": WINDSURF_BASE,
            "Referer": REGISTER_URL,
        }

    def warm_up(self) -> None:
        response = self.session.get(REGISTER_URL, timeout=self.timeout)
        response.raise_for_status()

    def check_user_login_method(self, email: str) -> bytes:
        payload = encode_len_field(1, email)
        response = self.session.post(
            CHECK_USER_LOGIN_METHOD_URL,
            data=payload,
            headers=self._proto_headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.content

    def get_connections(self, email: str) -> dict[str, Any]:
        response = self.session.post(
            CONNECTIONS_URL,
            headers=self._json_headers(),
            json={"product": "windsurf", "email": email},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def start_email_signup(self, email: str) -> str:
        response = self.session.post(
            EMAIL_START_URL,
            headers=self._json_headers(),
            json={"email": email, "mode": "signup", "product": "Windsurf"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        token = payload.get("email_verification_token")
        if not token:
            raise RuntimeError(f"email/start response missing token: {payload}")
        return token

    def complete_email_signup(
        self,
        email_verification_token: str,
        code: str,
        password: str,
        name: str,
    ) -> dict[str, Any]:
        response = self.session.post(
            EMAIL_COMPLETE_URL,
            headers=self._json_headers(),
            json={
                "email_verification_token": email_verification_token,
                "code": code,
                "mode": "signup",
                "password": password,
                "name": name,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if "token" not in payload:
            raise RuntimeError(f"email/complete response missing token: {payload}")
        return payload

    def post_auth(self, auth1_token: str) -> dict[str, str]:
        payload = encode_len_field(1, auth1_token)
        response = self.session.post(
            POST_AUTH_URL,
            data=payload,
            headers=self._proto_headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        parsed = parse_top_level_protobuf(response.content)
        try:
            return {
                "devin_session_token": decode_bytes(parsed[1][0]),
                "auth1_token": decode_bytes(parsed[3][0]),
                "account_id": decode_bytes(parsed[4][0]),
                "primary_org_id": decode_bytes(parsed[5][0]),
            }
        except (KeyError, IndexError) as exc:
            raise RuntimeError(
                f"unexpected WindsurfPostAuth protobuf response: {parsed!r}"
            ) from exc

    def get_current_user(
        self,
        auth1_token: str,
        devin_session_token: str,
        account_id: str,
        primary_org_id: str,
    ) -> bytes:
        payload = b"".join(
            [
                encode_len_field(1, devin_session_token),
                encode_varint_field(2, 1),
                encode_varint_field(4, 1),
            ]
        )
        headers = self._proto_headers()
        headers.update(
            {
                "x-auth-token": devin_session_token,
                "x-devin-session-token": devin_session_token,
                "x-devin-account-id": account_id,
                "x-devin-auth1-token": auth1_token,
                "x-devin-primary-org-id": primary_org_id,
            }
        )
        response = self.session.post(
            GET_CURRENT_USER_URL,
            data=payload,
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.content

    def fetch_show_auth_token_page(
        self,
        auth_headers: dict[str, str],
    ) -> str | None:
        response = self.session.get(
            f"{WINDSURF_BASE}/editor/show-auth-token?workflow=",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{WINDSURF_BASE}/editor/show-auth-token?workflow=",
                **auth_headers,
            },
            timeout=self.timeout,
            allow_redirects=True,
        )
        response.raise_for_status()
        return extract_pool_token_from_text(response.text)


def load_skymail_config(env_file: Path) -> SkyMailConfig:
    values = load_env_file(env_file)
    required = {
        "CLOUDMAIL_BASE_URL": values.get("CLOUDMAIL_BASE_URL", "").strip(),
        "CLOUDMAIL_ADMIN_EMAIL": values.get("CLOUDMAIL_ADMIN_EMAIL", "").strip(),
        "CLOUDMAIL_ADMIN_PASSWORD": values.get("CLOUDMAIL_ADMIN_PASSWORD", "").strip(),
        "CLOUDMAIL_DOMAIN": values.get("CLOUDMAIL_DOMAIN", "").strip(),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"Missing required env values in {env_file}: {', '.join(missing)}")
    if "your-cloudmail-host" in required["CLOUDMAIL_BASE_URL"]:
        raise RuntimeError(f"Fill CLOUDMAIL_BASE_URL in {env_file} before running the script.")
    return SkyMailConfig(
        base_url=required["CLOUDMAIL_BASE_URL"].rstrip("/"),
        admin_email=required["CLOUDMAIL_ADMIN_EMAIL"],
        admin_password=required["CLOUDMAIL_ADMIN_PASSWORD"],
        domain=required["CLOUDMAIL_DOMAIN"].lstrip("@"),
        email_prefix_length=read_int_setting(
            values,
            "EMAIL_PREFIX_LENGTH",
            DEFAULT_EMAIL_PREFIX_LENGTH,
        ),
        password_length=read_int_setting(
            values,
            "REGISTER_PASSWORD_LENGTH",
            DEFAULT_PASSWORD_LENGTH,
            minimum=8,
        ),
        display_name_length=read_int_setting(
            values,
            "DISPLAY_NAME_LENGTH",
            DEFAULT_DISPLAY_NAME_LENGTH,
            minimum=4,
        ),
        poll_interval_seconds=read_int_setting(
            values,
            "CLOUDMAIL_POLL_INTERVAL_SECONDS",
            DEFAULT_MAIL_POLL_INTERVAL_SECONDS,
        ),
        poll_timeout_seconds=read_int_setting(
            values,
            "CLOUDMAIL_POLL_TIMEOUT_SECONDS",
            DEFAULT_MAIL_POLL_TIMEOUT_SECONDS,
        ),
    )


def load_pool_api_base_url(env_file: Path) -> str:
    values = load_env_file(env_file)
    return (values.get("WINDSURF_POOL_API_BASE_URL", "") or DEFAULT_POOL_API_BASE_URL).rstrip("/")


def import_into_windsurf_pool(
    *,
    base_url: str,
    timeout: int,
    tokens: list[str],
) -> PoolImportResult:
    seen: set[str] = set()
    errors: list[str] = []
    for token in tokens:
        if not token or token in seen:
            continue
        seen.add(token)
        try:
            response = requests.post(
                f"{base_url}/auth/login",
                headers={"Content-Type": "application/json"},
                json={"token": token},
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            return PoolImportResult(token=token, response=payload)
        except Exception as exc:
            errors.append(f"{token[:16]}...: {exc}")
    raise RuntimeError(
        "Failed to import account into WindsurfPoolAPI via /auth/login. "
        f"Tried {len(seen)} token candidate(s). Errors: {' | '.join(errors)}"
    )


def resolve_runtime_args(args: argparse.Namespace) -> RuntimeConfig:
    env_file = args.env_file or Path(".env")
    skymail_config = load_skymail_config(env_file)
    pool_api_base_url = load_pool_api_base_url(env_file)

    count = args.count if args.count is not None else prompt_int("Register count", 1)
    if count < 1:
        raise RuntimeError("--count must be >= 1")
    output_dir = args.output_dir or Path(prompt_text("Output directory", "auth_output"))

    return RuntimeConfig(
        count=count,
        output_dir=output_dir.resolve(),
        env_file=env_file.resolve(),
        user_agent=args.user_agent,
        timeout=args.timeout,
        skymail=skymail_config,
        pool_api_base_url=pool_api_base_url,
    )


def build_account_seed(index: int, config: SkyMailConfig) -> AccountSeed:
    email_prefix = random_alnum(config.email_prefix_length)
    password = random_alnum(config.password_length)
    name = f"ws_{random_alnum(config.display_name_length)}"
    email = f"{email_prefix}@{config.domain}"
    return AccountSeed(index=index, email=email, password=password, name=name)


def save_account_artifacts(
    output_dir: Path,
    seed: AccountSeed,
    email_verification_token: str,
    login_method_raw: bytes,
    connections_payload: dict[str, Any],
    current_user_raw: bytes,
    cookies: list[dict[str, Any]],
    auth_headers: dict[str, str],
    post_auth_payload: dict[str, str],
) -> dict[str, str]:
    account_dir = output_dir / seed.email
    account_dir.mkdir(parents=True, exist_ok=True)

    pending_path = account_dir / "windsurf_pending_verification.json"
    session_path = account_dir / "windsurf_auth_session.json"
    storage_state_path = account_dir / "windsurf_storage_state.json"
    current_user_path = account_dir / "windsurf_current_user.pb.b64"

    save_json(
        pending_path,
        {
            "email": seed.email,
            "name": seed.name,
            "password": seed.password,
            "email_verification_token": email_verification_token,
            "connections": connections_payload,
            "check_user_login_method_b64": base64.b64encode(login_method_raw).decode("ascii"),
            "created_at": utc_now_iso(),
        },
    )

    playwright_payload = build_playwright_data(cookies=cookies, auth_headers=auth_headers)
    auth_data = WindsurfAuthData(
        email=seed.email,
        name=seed.name,
        auth1_token=post_auth_payload["auth1_token"],
        devin_session_token=post_auth_payload["devin_session_token"],
        account_id=post_auth_payload["account_id"],
        primary_org_id=post_auth_payload["primary_org_id"],
        email_verification_token=email_verification_token,
        created_at=utc_now_iso(),
        current_user_response_b64=base64.b64encode(current_user_raw).decode("ascii"),
        cookies=cookies,
        headers=auth_headers,
        playwright=playwright_payload,
    )

    save_json(session_path, asdict(auth_data))
    save_json(storage_state_path, playwright_payload["storage_state"])
    current_user_path.write_text(
        base64.b64encode(current_user_raw).decode("ascii"),
        encoding="ascii",
    )
    return {
        "account_dir": str(account_dir),
        "session_path": str(session_path),
        "storage_state_path": str(storage_state_path),
        "pending_verification_path": str(pending_path),
        "current_user_path": str(current_user_path),
    }


def append_registered_account(output_dir: Path, seed: AccountSeed, paths: dict[str, str]) -> None:
    credentials_path = output_dir / "registered_accounts.txt"
    if not credentials_path.exists():
        credentials_path.write_text(
            "created_at\temail\tpassword\tname\tsession_path\tstorage_state_path\n",
            encoding="utf-8",
        )
    line = (
        f"{utc_now_iso()}\t{seed.email}\t{seed.password}\t{seed.name}\t"
        f"{paths['session_path']}\t{paths['storage_state_path']}\n"
    )
    with credentials_path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def register_one_account(
    runtime: RuntimeConfig,
    skymail_client: SkyMailClient,
    seed: AccountSeed,
) -> dict[str, Any]:
    print(f"[{seed.index}/{runtime.count}] Creating mailbox {seed.email}", file=sys.stderr)
    skymail_client.add_user(seed.email, seed.password)

    registrar = WindsurfRegistrar(
        user_agent=runtime.user_agent,
        timeout=runtime.timeout,
    )
    registrar.warm_up()
    login_method_raw = registrar.check_user_login_method(seed.email)
    connections_payload = registrar.get_connections(seed.email)
    email_verification_token = registrar.start_email_signup(seed.email)

    print(
        f"[{seed.index}/{runtime.count}] Waiting for verification email: {seed.email}",
        file=sys.stderr,
    )
    code = skymail_client.wait_for_verification_code(
        to_email=seed.email,
        timeout_seconds=runtime.skymail.poll_timeout_seconds,
        interval_seconds=runtime.skymail.poll_interval_seconds,
    )

    completion_payload = registrar.complete_email_signup(
        email_verification_token=email_verification_token,
        code=code,
        password=seed.password,
        name=seed.name,
    )
    auth1_token = completion_payload["token"]
    post_auth_payload = registrar.post_auth(auth1_token)
    current_user_raw = registrar.get_current_user(
        auth1_token=post_auth_payload["auth1_token"],
        devin_session_token=post_auth_payload["devin_session_token"],
        account_id=post_auth_payload["account_id"],
        primary_org_id=post_auth_payload["primary_org_id"],
    )

    cookies = [cookie_to_dict(cookie) for cookie in registrar.session.cookies]
    auth_headers = {
        "x-auth-token": post_auth_payload["devin_session_token"],
        "x-devin-session-token": post_auth_payload["devin_session_token"],
        "x-devin-account-id": post_auth_payload["account_id"],
        "x-devin-auth1-token": post_auth_payload["auth1_token"],
        "x-devin-primary-org-id": post_auth_payload["primary_org_id"],
    }
    show_auth_token = None
    try:
        show_auth_token = registrar.fetch_show_auth_token_page(auth_headers)
    except Exception as exc:
        print(
            f"[{seed.index}/{runtime.count}] show-auth-token fetch failed for {seed.email}: {exc}",
            file=sys.stderr,
        )

    pool_import = import_into_windsurf_pool(
        base_url=runtime.pool_api_base_url,
        timeout=runtime.timeout,
        tokens=[
            show_auth_token or "",
            post_auth_payload["auth1_token"],
            post_auth_payload["devin_session_token"],
        ],
    )
    paths = save_account_artifacts(
        output_dir=runtime.output_dir,
        seed=seed,
        email_verification_token=email_verification_token,
        login_method_raw=login_method_raw,
        connections_payload=connections_payload,
        current_user_raw=current_user_raw,
        cookies=cookies,
        auth_headers=auth_headers,
        post_auth_payload=post_auth_payload,
    )
    append_registered_account(runtime.output_dir, seed, paths)
    print(seed.email)
    return {
        "email": seed.email,
        "password": seed.password,
        "name": seed.name,
        "account_id": post_auth_payload["account_id"],
        "primary_org_id": post_auth_payload["primary_org_id"],
        "pool_import": pool_import.response,
        **paths,
    }


def run(args: argparse.Namespace) -> int:
    runtime = resolve_runtime_args(args)
    runtime.output_dir.mkdir(parents=True, exist_ok=True)

    skymail_client = SkyMailClient(
        config=runtime.skymail,
        user_agent=runtime.user_agent,
        timeout=runtime.timeout,
    )
    skymail_client.authenticate()

    successes: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index in range(1, runtime.count + 1):
        seed = build_account_seed(index=index, config=runtime.skymail)
        try:
            result = register_one_account(runtime=runtime, skymail_client=skymail_client, seed=seed)
            successes.append(result)
        except Exception as exc:
            failures.append(
                {
                    "index": index,
                    "email": seed.email,
                    "name": seed.name,
                    "password": seed.password,
                    "error": str(exc),
                }
            )
            print(f"[{index}/{runtime.count}] Failed {seed.email}: {exc}", file=sys.stderr)

    summary = {
        "requested_count": runtime.count,
        "success_count": len(successes),
        "failure_count": len(failures),
        "output_dir": str(runtime.output_dir),
        "credentials_txt": str(runtime.output_dir / "registered_accounts.txt"),
        "successes": successes,
        "failures": failures,
    }
    summary_path = runtime.output_dir / f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_json(summary_path, {**summary, "summary_path": str(summary_path)})
    if failures:
        print(
            f"Batch finished with {len(failures)} failure(s). See {summary_path}",
            file=sys.stderr,
        )
    return 0 if not failures else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, help="How many accounts to register in this run")
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Path to the env file containing CloudMail admin settings",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory used to save per-account auth artifacts",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="HTTP user-agent used for the registration flow",
    )
    parser.add_argument(
        "--timeout",
        default=30,
        type=int,
        help="HTTP timeout in seconds",
    )
    return parser


if __name__ == "__main__":
    try:
        raise SystemExit(run(build_parser().parse_args()))
    except requests.HTTPError as exc:
        response = exc.response
        details = {
            "status_code": response.status_code if response is not None else None,
            "url": response.url if response is not None else None,
            "body": response.text[:2000] if response is not None else None,
        }
        print(json.dumps(details, indent=2, ensure_ascii=False), file=sys.stderr)
        raise
