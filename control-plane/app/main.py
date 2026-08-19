from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import ssl
import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import jwt
import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from ldap3 import ALL, BASE, SUBTREE, Connection, Server as LDAPServer, Tls
from ldap3.utils.conv import escape_filter_chars
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, create_engine, delete, func, inspect, select, text, update
from sqlalchemy.engine import Engine, URL
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .file_security import MalwareDetected, ScannerUnavailable, decrypt_file, encrypt_file, normalize_upload_name, scan_with_clamav
from .agent_packages import LINUX_AGENT_PATH, certificate_sha256, linux_run_bundle, safe_package_label, validate_linux_agent, validate_windows_msi, windows_msi_filename
from .tunnel import TunnelHub


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = ""
    jwt_secret: str = ""
    jwt_issuer: str = "tram-van-hanh"
    jwt_ttl_minutes: int = 480
    bootstrap_admin_user: str = "admin"
    bootstrap_admin_password: str = ""
    agent_ca_cert: str = "/run/secrets/agent-ca.crt"
    agent_ca_key: str = "/run/secrets/agent-ca.key"
    agent_cert_days: int = 90
    caddy_root_ca: str = "/caddy-data/caddy/pki/authorities/local/root.crt"
    guacamole_url: str = "/guacamole"
    guacamole_json_secret: str = ""
    job_secret_key: str = ""
    allowed_origins: str = ""
    allowed_hosts: str = ""
    recording_root: str = "/recordings"
    bootstrap_config_path: str = "/var/lib/tram-ops/bootstrap.json"
    setup_token: str = ""
    dashboard_url: str = ""
    tunnel_bind_host: str = "0.0.0.0"
    tunnel_relay_host: str = "api"
    tunnel_listener_ttl_seconds: int = 120
    tunnel_connect_timeout_seconds: int = 20
    tunnel_max_sessions_per_agent: int = 4
    file_max_bytes: int = 50 * 1024 * 1024
    file_transfer_ttl_hours: int = 24
    audit_retention_days: int = Field(default=30, ge=1, le=3650)
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_timeout_seconds: int = 60
    agent_assets_root: str = "/opt/tram-agent-assets"
    windows_agent_msi: str = "/opt/tram-agent-assets/windows/TramVanHanhAgent.msi"
    web_tls_trust: Literal["internal-ca", "system"] = "internal-ca"
    auth_window_seconds: int = Field(default=300, ge=60, le=3600)
    auth_lockout_seconds: int = Field(default=900, ge=60, le=86400)
    auth_account_failures: int = Field(default=5, ge=3, le=20)
    auth_ip_failures: int = Field(default=30, ge=10, le=200)


settings = Settings()
bootstrap_path = Path(settings.bootstrap_config_path)


def read_release_version() -> str:
    candidates = (
        Path(settings.agent_assets_root) / "VERSION",
        Path(__file__).resolve().parents[2] / "agent" / "VERSION",
    )
    for candidate in candidates:
        try:
            version = candidate.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            return version
        raise RuntimeError(f"Invalid release VERSION file: {candidate}")
    raise RuntimeError("Release VERSION file is unavailable")


RELEASE_VERSION = read_release_version()
AGENT_SERVER_CA_UNAVAILABLE = (
    "CA TLS của kênh Agent chưa sẵn sàng; hãy kiểm tra dịch vụ "
    "caddy-ca-export rồi triển khai lại API."
)


def read_agent_server_ca() -> tuple[str, str]:
    try:
        certificate = Path(settings.caddy_root_ca).read_text(encoding="utf-8")
        fingerprint = certificate_sha256(certificate)
    except (OSError, UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=AGENT_SERVER_CA_UNAVAILABLE) from exc
    return certificate, fingerprint


def agent_server_ca_available() -> bool:
    try:
        read_agent_server_ca()
    except HTTPException:
        return False
    return True


def read_bootstrap_config() -> dict[str, str]:
    try:
        raw = json.loads(bootstrap_path.read_text(encoding="utf-8"))
        return {str(key): str(value) for key, value in raw.items() if value is not None}
    except (OSError, ValueError, TypeError):
        return {}


bootstrap_config = read_bootstrap_config()
settings.database_url = settings.database_url or bootstrap_config.get("database_url", "")
settings.jwt_secret = settings.jwt_secret or bootstrap_config.get("jwt_secret", "")
settings.job_secret_key = settings.job_secret_key or bootstrap_config.get("job_secret_key", "")
password_hasher = PasswordHasher()
engine: Engine | None = create_engine(settings.database_url, pool_pre_ping=True) if settings.database_url else None
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False) if engine else None
database_lock = threading.RLock()
database_error = ""


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(String(160), default="")
    role: Mapped[str] = mapped_column(String(30), default="viewer")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class PlatformRole(Base):
    __tablename__ = "platform_roles"
    name: Mapped[str] = mapped_column(String(30), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    system: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))


class PlatformGroup(Base):
    __tablename__ = "platform_groups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class PlatformGroupMember(Base):
    __tablename__ = "platform_group_members"
    group_id: Mapped[str] = mapped_column(ForeignKey("platform_groups.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class ServerUserShare(Base):
    __tablename__ = "server_user_shares"
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    granted_by: Mapped[str] = mapped_column(String(36))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class ServerGroupShare(Base):
    __tablename__ = "server_group_shares"
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("platform_groups.id"), primary_key=True)
    granted_by: Mapped[str] = mapped_column(String(36))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class ServerRetirement(Base):
    __tablename__ = "server_retirements"
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), primary_key=True)
    retired_by: Mapped[str] = mapped_column(String(36), index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class MFACredential(Base):
    __tablename__ = "mfa_credentials"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    secret_encrypted: Mapped[str] = mapped_column(Text)
    enrolled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_counter: Mapped[int] = mapped_column(Integer, default=-1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class AuthThrottle(Base):
    __tablename__ = "auth_throttles"
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class Server(Base):
    __tablename__ = "servers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    os_family: Mapped[str] = mapped_column(String(20), index=True)
    os_name: Mapped[str] = mapped_column(String(120))
    os_version: Mapped[str] = mapped_column(String(120), default="")
    distribution_id: Mapped[str] = mapped_column(String(80), default="")
    architecture: Mapped[str] = mapped_column(String(50), default="")
    address: Mapped[str] = mapped_column(String(120), default="")
    environment: Mapped[str] = mapped_column(String(40), default="Unassigned")
    owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    agent_version: Mapped[str] = mapped_column(String(30), default="")
    cert_fingerprint: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True, index=True)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    status: Mapped[str] = mapped_column(String(30), default="enrolling")
    cpu_percent: Mapped[float] = mapped_column(Float, default=0)
    memory_percent: Mapped[float] = mapped_column(Float, default=0)
    disk_percent: Mapped[float] = mapped_column(Float, default=0)
    uptime_seconds: Mapped[int] = mapped_column(Integer, default=0)
    pending_updates: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    services_running: Mapped[int] = mapped_column(Integer, default=0)
    inventory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ssh_host_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    remote_protocol: Mapped[str] = mapped_column(String(10), default="ssh")
    verified_os: Mapped[bool] = mapped_column(Boolean, default=True)
    jobs: Mapped[list["Job"]] = relationship(back_populates="server")


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    expected_os_family: Mapped[str | None] = mapped_column(String(20), nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(36))


class AgentBootstrapPackage(Base):
    __tablename__ = "agent_bootstrap_packages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    expected_os_family: Mapped[str] = mapped_column(String(20), index=True)
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    risk: Mapped[str] = mapped_column(String(20), default="medium")
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[str] = mapped_column(Text, default="")
    server: Mapped[Server] = relationship(back_populates="jobs")


class BulkTask(Base):
    __tablename__ = "bulk_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action: Mapped[str] = mapped_column(String(80), index=True)
    os_family: Mapped[str] = mapped_column(String(20), index=True)
    target_count: Mapped[int] = mapped_column(Integer)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class BulkTaskItem(Base):
    __tablename__ = "bulk_task_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    bulk_task_id: Mapped[str] = mapped_column(ForeignKey("bulk_tasks.id"), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), unique=True, index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    actor: Mapped[str] = mapped_column(String(160), index=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    result: Mapped[str] = mapped_column(String(30), default="success")
    source_ip: Mapped[str] = mapped_column(String(100), default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))


class RemoteSession(Base):
    __tablename__ = "remote_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(10))
    remote_username: Mapped[str] = mapped_column(String(128))
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(30), default="launched", index=True)
    recording_name: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RecordingDeletionRequest(Base):
    __tablename__ = "recording_deletion_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    requested_by_username: Mapped[str] = mapped_column(String(80))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    approved_by_username: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


class FileTransfer(Base):
    __tablename__ = "file_transfers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id"), nullable=True, index=True)
    original_name: Mapped[str] = mapped_column(String(180))
    content_type: Mapped[str] = mapped_column(String(255), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), default="scanning", index=True)
    scan_result: Mapped[str] = mapped_column(String(255), default="")
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(36), index=True)
    content_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    nonce: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=1024)
    source: Literal["local", "domain"] = "local"


class MFAVerifyRequest(BaseModel):
    challenge_token: str
    code: str = Field(pattern=r"^\d{6}$")


class PlatformUserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.@-]+$")
    display_name: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=14, max_length=1024)
    role: str = Field(default="viewer", min_length=1, max_length=30, pattern=r"^[a-z][a-z0-9_-]*$")


class PlatformUserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=160)
    role: str | None = Field(default=None, min_length=1, max_length=30, pattern=r"^[a-z][a-z0-9_-]*$")
    enabled: bool | None = None
    password: str | None = Field(default=None, min_length=14, max_length=1024)


class PlatformUsersDeleteRequest(BaseModel):
    user_ids: list[str] = Field(min_length=1, max_length=100)


class PlatformRoleRequest(BaseModel):
    name: str = Field(min_length=2, max_length=30, pattern=r"^[a-z][a-z0-9_-]*$")
    display_name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    permissions: list[str] = Field(default_factory=list, max_length=64)


class PlatformRoleUpdateRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    permissions: list[str] = Field(default_factory=list, max_length=64)


class PlatformGroupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9À-ỹ_.@ -]+$")
    description: str = Field(default="", max_length=1000)
    member_ids: list[str] = Field(default_factory=list, max_length=500)


class PlatformGroupMembersRequest(BaseModel):
    member_ids: list[str] = Field(default_factory=list, max_length=500)


class ServerSharesRequest(BaseModel):
    user_ids: list[str] = Field(default_factory=list, max_length=500)
    group_ids: list[str] = Field(default_factory=list, max_length=500)


class ServerDeleteRequest(BaseModel):
    confirmation: str = Field(pattern=r"^DELETE$")
    reason: str = Field(min_length=3, max_length=500)


class LDAPConfigRequest(BaseModel):
    enabled: bool = False
    host: str = Field(default="", max_length=255)
    port: int = Field(default=636, ge=1, le=65535)
    use_ssl: bool = True
    base_dn: str = Field(default="", max_length=512)
    bind_dn: str = Field(default="", max_length=512)
    bind_password: str = Field(default="", max_length=1024)
    ca_certificate: str = Field(default="", max_length=65536)
    user_attribute: str = Field(default="sAMAccountName", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
    display_attribute: str = Field(default="displayName", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
    domain_label: str = Field(default="DOMAIN", pattern=r"^[A-Za-z0-9_.-]{1,15}$")
    default_role: str = Field(default="viewer", min_length=1, max_length=30, pattern=r"^[a-z][a-z0-9_-]*$")
    allowed_group_dns: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("allowed_group_dns")
    @classmethod
    def valid_allowed_group_dns(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if len(set(value.casefold() for value in normalized)) != len(normalized) or any(not value or len(value) > 512 or any(ord(character) < 32 for character in value) for value in normalized):
            raise ValueError("LDAP group DN list is invalid or contains duplicates")
        return normalized


class EnrollmentTokenRequest(BaseModel):
    label: str = ""
    expected_os_family: Literal["windows", "linux"] | None = None
    expires_hours: int = Field(default=24, ge=1, le=168)
    max_uses: int = Field(default=1, ge=1, le=1000)


class AgentPackageRequest(BaseModel):
    label: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_.@ -]+$")
    os_family: Literal["windows", "linux"]
    expires_minutes: int = Field(default=30, ge=5, le=60)


class DashboardUrlUpdateRequest(BaseModel):
    dashboard_url: str = Field(min_length=8, max_length=2048)
    confirm_existing_agents: bool = False

    @field_validator("dashboard_url")
    @classmethod
    def valid_dashboard_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Dashboard URL must be an origin-only absolute HTTPS URL")
        return normalized


class Inventory(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_family: Literal["windows", "linux"]
    os_name: str = Field(min_length=1, max_length=120)
    os_version: str = Field(default="", max_length=120)
    distribution_id: str = Field(default="", max_length=80)
    architecture: str = Field(default="", max_length=50)
    agent_version: str = Field(default="", max_length=30)
    addresses: list[str] = Field(default_factory=list, max_length=32)
    boot_id: str = Field(default="", max_length=128)
    ssh_host_key: str | None = Field(default=None, max_length=8192)
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("distribution_id")
    @classmethod
    def supported_distribution(cls, value: str) -> str:
        return value.lower().strip()


class EnrollmentRequest(BaseModel):
    token: str = Field(min_length=20)
    agent_id: str
    csr_pem: str
    inventory: Inventory


class AgentBootstrapClaimRequest(BaseModel):
    package_id: str
    package_secret: str = Field(min_length=32, max_length=256)
    agent_id: str
    csr_pem: str
    inventory: Inventory


class Metrics(BaseModel):
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    disk_percent: float = Field(ge=0, le=100)
    uptime_seconds: int = Field(ge=0)
    pending_updates: int | None = Field(default=None, ge=0)
    services_running: int | None = Field(default=None, ge=0)
    alerts: int = Field(default=0, ge=0)


class CheckinRequest(BaseModel):
    agent_id: str
    agent_version: str
    active_job_id: str | None = Field(default=None, max_length=36)
    active_job_ids: list[str] = Field(default_factory=list, max_length=4)
    inventory: Inventory | None = None
    metrics: Metrics

    @field_validator("active_job_ids")
    @classmethod
    def valid_active_job_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(not re.fullmatch(r"[A-Za-z0-9-]{1,36}", value) for value in values):
            raise ValueError("Agent active job IDs are invalid")
        return values


class JobCreateRequest(BaseModel):
    server_id: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2000)


class BulkTaskCreateRequest(BaseModel):
    os_family: Literal["windows", "linux"]
    server_ids: list[str] = Field(min_length=1, max_length=100)
    action: Literal["user.create", "firewall.rule.add.auto"]
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2000)

    @field_validator("server_ids")
    @classmethod
    def valid_server_ids(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9-]{1,36}", value) for value in values):
            raise ValueError("Target server ID is invalid")
        if len(values) != len(set(values)):
            raise ValueError("Duplicate target servers are not allowed")
        return values


class JobResultRequest(BaseModel):
    status: Literal["succeeded", "failed"]
    exit_code: int
    output: str = Field(default="", max_length=5_000_000)


class LogSourcesUpdateRequest(BaseModel):
    sources: list[str] = Field(min_length=1, max_length=20)


class SessionLaunchRequest(BaseModel):
    server_id: str
    protocol: Literal["ssh", "rdp"]
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    width: int = Field(default=1440, ge=800, le=7680)
    height: int = Field(default=900, ge=600, le=4320)


class RecordingDeletionCreateRequest(BaseModel):
    session_ids: list[str] = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=5, max_length=1000)


class RecordingRetentionRequest(BaseModel):
    enabled: bool = True
    days: int = Field(default=180, ge=30, le=3650)


class DatabaseSetupRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9_.-]+$")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    sslmode: Literal["disable", "prefer", "require", "verify-ca", "verify-full"] = "prefer"


class InitialAdminRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.@-]+$")
    display_name: str = Field(default="Administrator", min_length=1, max_length=160)
    password: str = Field(min_length=14, max_length=1024)


class SetupCompleteRequest(BaseModel):
    database: DatabaseSetupRequest
    admin: InitialAdminRequest
    dashboard_url: str = Field(min_length=8, max_length=2048)
    setup_token: str = Field(default="", max_length=512)

    @field_validator("dashboard_url")
    @classmethod
    def valid_dashboard_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Dashboard URL must be an origin-only absolute HTTPS URL")
        return normalized


SAFE_ACTIONS: dict[str, dict[str, Any]] = {
    "inventory.collect": {"roles": {"admin", "operator"}, "risk": "low"},
    "service.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "service.restart": {"roles": {"admin", "operator"}, "risk": "medium"},
    "service.start": {"roles": {"admin", "operator"}, "risk": "medium"},
    "service.stop": {"roles": {"admin", "operator"}, "risk": "high"},
    "user.create": {"roles": {"admin", "operator"}, "risk": "high"},
    "user.update": {"roles": {"admin", "operator"}, "risk": "high"},
    "user.disable": {"roles": {"admin", "operator"}, "risk": "high"},
    "user.enable": {"roles": {"admin", "operator"}, "risk": "high"},
    "user.delete": {"roles": {"admin", "operator"}, "risk": "critical"},
    "user.password.reset": {"roles": {"admin", "operator"}, "risk": "high"},
    "group.create": {"roles": {"admin", "operator"}, "risk": "medium"},
    "group.delete": {"roles": {"admin", "operator"}, "risk": "critical"},
    "user.add_group": {"roles": {"admin", "operator"}, "risk": "high"},
    "group.remove_user": {"roles": {"admin", "operator"}, "risk": "high"},
    "user.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "group.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "patch.scan": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "patch.install": {"roles": {"admin", "operator"}, "risk": "high"},
    "logs.sources": {"roles": {"admin", "operator", "viewer", "auditor"}, "risk": "low"},
    "logs.read": {"roles": {"admin", "operator", "viewer", "auditor"}, "risk": "low"},
    "process.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "process.kill": {"roles": {"admin", "operator"}, "risk": "high"},
    "firewall.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "firewall.rule.add": {"roles": {"admin", "operator"}, "risk": "high"},
    "firewall.rule.add.auto": {"roles": {"admin", "operator"}, "risk": "high"},
    "firewall.rule.remove": {"roles": {"admin", "operator"}, "risk": "high"},
    "firewall.rule.reorder": {"roles": {"admin", "operator"}, "risk": "critical"},
    "storage.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "storage.extend": {"roles": {"admin", "operator"}, "risk": "critical"},
    "storage.shrink": {"roles": {"admin", "operator"}, "risk": "critical"},
    "storage.create": {"roles": {"admin", "operator"}, "risk": "critical"},
    "storage.delete": {"roles": {"admin", "operator"}, "risk": "critical"},
    "network.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low"},
    "system.reboot": {"roles": {"admin", "operator"}, "risk": "critical"},
}

MAX_CONCURRENT_AGENT_JOBS = 4
PARALLEL_AGENT_READ_ACTIONS = {action for action, policy in SAFE_ACTIONS.items() if policy["risk"] == "low"}

PERMISSION_CATALOG: dict[str, dict[str, str]] = {
    "servers.view": {"group": "Máy chủ", "label": "Xem danh sách máy chủ", "description": "Xem inventory, tình trạng và trang chi tiết máy chủ."},
    "servers.manage": {"group": "Máy chủ", "label": "Xóa và chia sẻ máy chủ", "description": "Ẩn/ngừng Agent và gán quyền nhìn thấy máy chủ cho user/group."},
    "resources.view": {"group": "Máy chủ", "label": "Xem tài nguyên vận hành", "description": "Quét và xem Services, tài khoản, firewall, disk, process, update và network."},
    "sessions.launch": {"group": "Phiên truy cập", "label": "Mở SSH / Remote Desktop", "description": "Khởi tạo phiên quản trị qua tunnel mTLS của Agent."},
    "recordings.view": {"group": "Phiên truy cập", "label": "Xem recording", "description": "Xem danh sách và phát lại recording SSH/RDP."},
    "recordings.delete": {"group": "Phiên truy cập", "label": "Xóa recording", "description": "Xóa recording theo luồng kiểm soát và audit hiện hành."},
    "services.manage": {"group": "Vận hành", "label": "Điều khiển Services", "description": "Start, Stop và Restart service."},
    "accounts.manage": {"group": "Vận hành", "label": "Quản lý tài khoản máy chủ", "description": "Tạo, sửa, khóa, xóa user/group trên máy chủ được quản trị."},
    "firewall.manage": {"group": "Vận hành", "label": "Quản lý Firewall", "description": "Thêm, xóa và sắp xếp firewall rule."},
    "storage.manage": {"group": "Vận hành", "label": "Quản lý Disk", "description": "Extend, Shrink, tạo và xóa partition/LVM/volume."},
    "processes.manage": {"group": "Vận hành", "label": "Kill process", "description": "Dừng process đã chọn sau khi Agent đối chiếu PID."},
    "updates.manage": {"group": "Vận hành", "label": "Cài bản cập nhật", "description": "Cài đúng các gói update được chọn."},
    "logs.view": {"group": "Vận hành", "label": "Xem và cấu hình log", "description": "Đọc tối đa 500 dòng và chọn nguồn log cho từng máy chủ."},
    "files.view": {"group": "Vận hành", "label": "Xem lịch sử truyền file", "description": "Xem metadata, trạng thái quét và kết quả giao file."},
    "files.manage": {"group": "Vận hành", "label": "Gửi file", "description": "Quét malware và gửi file tới Agent."},
    "system.reboot": {"group": "Vận hành", "label": "Khởi động lại máy chủ", "description": "Lên lịch reboot máy chủ từ Agent."},
    "audit.view": {"group": "Quản trị website", "label": "Xem nhật ký kiểm toán", "description": "Đọc audit log và chuỗi hash liên kết."},
    "users.manage": {"group": "Quản trị website", "label": "Quản lý người dùng", "description": "Tạo, sửa role/mật khẩu/trạng thái và xóa tài khoản website."},
    "ldap.manage": {"group": "Quản trị website", "label": "Cấu hình LDAP", "description": "Thay đổi kết nối LDAP/Active Directory và role mặc định."},
    "roles.manage": {"group": "Quản trị website", "label": "Quản lý role", "description": "Tạo, sửa và xóa role tùy chỉnh."},
    "agents.manage": {"group": "Quản trị website", "label": "Quản lý Agent", "description": "Tạo token/bộ cài Agent và thay đổi URL dashboard."},
}

ACTION_PERMISSIONS: dict[str, str] = {
    "inventory.collect": "resources.view",
    "service.list": "resources.view",
    "service.restart": "services.manage",
    "service.start": "services.manage",
    "service.stop": "services.manage",
    "user.create": "accounts.manage",
    "user.update": "accounts.manage",
    "user.disable": "accounts.manage",
    "user.enable": "accounts.manage",
    "user.delete": "accounts.manage",
    "user.password.reset": "accounts.manage",
    "group.create": "accounts.manage",
    "group.delete": "accounts.manage",
    "user.add_group": "accounts.manage",
    "group.remove_user": "accounts.manage",
    "user.list": "resources.view",
    "group.list": "resources.view",
    "patch.scan": "resources.view",
    "patch.install": "updates.manage",
    "logs.sources": "logs.view",
    "logs.read": "logs.view",
    "process.list": "resources.view",
    "process.kill": "processes.manage",
    "firewall.list": "resources.view",
    "firewall.rule.add": "firewall.manage",
    "firewall.rule.add.auto": "firewall.manage",
    "firewall.rule.remove": "firewall.manage",
    "firewall.rule.reorder": "firewall.manage",
    "storage.list": "resources.view",
    "storage.extend": "storage.manage",
    "storage.shrink": "storage.manage",
    "storage.create": "storage.manage",
    "storage.delete": "storage.manage",
    "network.list": "resources.view",
    "system.reboot": "system.reboot",
    "file.deliver": "files.manage",
}

ALL_PLATFORM_PERMISSIONS = set(PERMISSION_CATALOG)
BUILTIN_ROLE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "admin": {"display_name": "Administrator", "description": "Toàn quyền quản trị website và máy chủ.", "permissions": sorted(ALL_PLATFORM_PERMISSIONS)},
    "operator": {"display_name": "Operator", "description": "Vận hành các máy chủ được chia sẻ, phiên truy cập và file; không quản trị danh tính website.", "permissions": sorted(ALL_PLATFORM_PERMISSIONS - {"audit.view", "users.manage", "ldap.manage", "roles.manage", "agents.manage", "recordings.delete", "servers.manage"})},
    "viewer": {"display_name": "Viewer", "description": "Chỉ xem fleet và dữ liệu tài nguyên; không thực hiện thay đổi.", "permissions": ["logs.view", "resources.view", "servers.view"]},
    "auditor": {"display_name": "Auditor", "description": "Xem fleet, log, audit, file và recording; không thay đổi máy chủ.", "permissions": ["audit.view", "files.view", "logs.view", "recordings.view", "servers.view"]},
}

AUTO_REFRESH_ACTIONS: dict[str, tuple[str, ...]] = {
    "firewall.rule.add": ("firewall.list",),
    "firewall.rule.add.auto": ("firewall.list",),
    "firewall.rule.remove": ("firewall.list",),
    "firewall.rule.reorder": ("firewall.list",),
    "service.start": ("service.list",),
    "service.stop": ("service.list",),
    "service.restart": ("service.list",),
    "user.create": ("user.list", "group.list"),
    "user.update": ("user.list", "group.list"),
    "user.disable": ("user.list",),
    "user.enable": ("user.list",),
    "user.delete": ("user.list", "group.list"),
    "user.password.reset": ("user.list",),
    "user.add_group": ("user.list", "group.list"),
    "group.remove_user": ("user.list", "group.list"),
    "group.create": ("group.list",),
    "group.delete": ("group.list", "user.list"),
    "storage.extend": ("storage.list",),
    "storage.shrink": ("storage.list",),
    "storage.create": ("storage.list",),
    "storage.delete": ("storage.list",),
    "process.kill": ("process.list",),
    "patch.install": ("patch.scan",),
}


def validate_firewall_job_parameters(action: str, parameters: dict[str, Any]) -> None:
    if action == "firewall.list":
        if parameters:
            raise HTTPException(status_code=422, detail="firewall.list does not accept parameters")
        return
    if action == "firewall.rule.add.auto":
        allowed = {"name", "direction", "action", "protocol", "local_port", "remote_port", "source", "destination", "family"}
        required = {"name", "direction", "action", "protocol", "local_port", "family"}
        if set(parameters) - allowed or not required.issubset(parameters):
            raise HTTPException(status_code=422, detail="Common firewall rule parameters are incomplete")
        if parameters.get("direction") not in {"in", "out"} or parameters.get("action") not in {"allow", "deny", "reject"} or parameters.get("protocol") not in {"tcp", "udp"}:
            raise HTTPException(status_code=422, detail="Common firewall direction, action or protocol is invalid")
        if parameters.get("family") not in {"ipv4", "ipv6"}:
            raise HTTPException(status_code=422, detail="Common firewall IP family is invalid")
        for key in ("local_port", "remote_port"):
            value = parameters.get(key, "any")
            if str(value).lower() == "any" and key == "remote_port":
                continue
            try:
                port = int(value)
            except (TypeError, ValueError):
                raise HTTPException(status_code=422, detail=f"Firewall {key} is invalid") from None
            if not 1 <= port <= 65535:
                raise HTTPException(status_code=422, detail=f"Firewall {key} is invalid")
        name = str(parameters.get("name", "")).strip()
        if not 1 <= len(name) <= 128 or any(ord(character) < 32 for character in name):
            raise HTTPException(status_code=422, detail="Firewall rule name is invalid")
        expected_ip_version = 4 if parameters["family"] == "ipv4" else 6
        for key in ("source", "destination"):
            value = str(parameters.get(key, "any")).strip().lower()
            if value in {"", "any"}:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise HTTPException(status_code=422, detail=f"Firewall {key} CIDR is invalid") from None
            if network.version != expected_ip_version:
                raise HTTPException(status_code=422, detail=f"Firewall {key} does not match the selected IP family")
        if len(json.dumps(parameters, ensure_ascii=False)) > 10_000:
            raise HTTPException(status_code=422, detail="Firewall rule parameters are too large")
        return
    if action == "firewall.rule.add":
        allowed = {"backend", "name", "direction", "action", "protocol", "local_port", "remote_port", "source", "destination", "profile", "zone", "family", "table", "chain"}
        if set(parameters) - allowed:
            raise HTTPException(status_code=422, detail="Unknown firewall rule parameter")
        required = {"backend", "name", "direction", "action", "protocol", "local_port"}
        if not required.issubset(parameters):
            raise HTTPException(status_code=422, detail="Firewall rule parameters are incomplete")
        backend = str(parameters.get("backend", "")).lower()
        direction = str(parameters.get("direction", "")).lower()
        if backend not in {"windows", "ufw", "firewalld", "nftables", "iptables"} or direction not in {"in", "out"}:
            raise HTTPException(status_code=422, detail="Firewall backend or direction is invalid")
        if parameters.get("protocol") not in {"tcp", "udp"} or parameters.get("action") not in {"allow", "deny", "reject"}:
            raise HTTPException(status_code=422, detail="Firewall protocol or action is invalid")
        if backend == "firewalld" and (direction != "in" or not parameters.get("zone") or parameters.get("family") not in {"ipv4", "ipv6"}):
            raise HTTPException(status_code=422, detail="firewalld requires an inbound zone and IP family reported by the server")
        if backend in {"nftables", "iptables"}:
            if not all(parameters.get(key) for key in ("family", "table", "chain")) or parameters.get("table") != "filter":
                raise HTTPException(status_code=422, detail="Netfilter requires a filter chain reported by the server")
        if backend == "windows" and parameters.get("profile") not in {"Any", "Domain", "Private", "Public"}:
            raise HTTPException(status_code=422, detail="Windows Firewall profile is invalid")
        if str(parameters.get("local_port", "")).lower() == "any" and not (backend == "windows" and direction == "out"):
            raise HTTPException(status_code=422, detail="Only outbound Windows rules may use any local port")
        for key in ("name", "source", "destination"):
            if not isinstance(parameters.get(key, ""), str) or len(str(parameters.get(key, ""))) > 512:
                raise HTTPException(status_code=422, detail=f"Firewall {key} is invalid")
        if len(json.dumps(parameters, ensure_ascii=False)) > 10_000:
            raise HTTPException(status_code=422, detail="Firewall rule parameters are too large")
        return
    if action == "firewall.rule.remove":
        if set(parameters) != {"rules"} or not isinstance(parameters.get("rules"), list):
            raise HTTPException(status_code=422, detail="Firewall deletion requires a rules list")
        rules = parameters["rules"]
        if not 1 <= len(rules) <= 200 or any(not isinstance(rule, dict) for rule in rules):
            raise HTTPException(status_code=422, detail="Select between 1 and 200 firewall rules")
        if len(json.dumps(parameters, ensure_ascii=False)) > 200_000:
            raise HTTPException(status_code=422, detail="Selected firewall rules are too large")
        return
    if action == "firewall.rule.reorder":
        if set(parameters) - {"rule", "before"} or "rule" not in parameters:
            raise HTTPException(status_code=422, detail="Firewall reorder requires rule and optional before target")
        if not isinstance(parameters.get("rule"), dict) or (parameters.get("before") is not None and not isinstance(parameters.get("before"), dict)):
            raise HTTPException(status_code=422, detail="Firewall reorder rules are invalid")
        source = parameters["rule"]
        target = parameters.get("before")
        if source.get("backend") not in {"ufw", "nftables", "iptables"} or (target and target.get("backend") != source.get("backend")):
            raise HTTPException(status_code=422, detail="Firewall backend does not support ordered rules")
        if len(json.dumps(parameters, ensure_ascii=False)) > 50_000:
            raise HTTPException(status_code=422, detail="Firewall reorder parameters are too large")


def validate_job_parameters(action: str, parameters: dict[str, Any], server: Server) -> None:
    if len(json.dumps(parameters, ensure_ascii=False)) > 250_000:
        raise HTTPException(status_code=422, detail="Job parameters are too large")
    if action.startswith("firewall."):
        validate_firewall_job_parameters(action, parameters)
        return
    empty_actions = {"inventory.collect", "service.list", "user.list", "group.list", "patch.scan", "logs.sources", "process.list", "storage.list", "network.list", "system.reboot"}
    if action in empty_actions:
        if parameters:
            raise HTTPException(status_code=422, detail=f"{action} does not accept parameters")
        return
    if action in {"service.start", "service.stop", "service.restart"}:
        if set(parameters) != {"name"} or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,160}", str(parameters.get("name", ""))):
            raise HTTPException(status_code=422, detail="Select a valid service reported by the server")
        return
    if action == "user.create":
        allowed = {"username", "password", "groups", "is_admin"}
        username_pattern = r"[^\\/\[\]:;|=,+*?<>@\x00-\x1f]{1,20}" if server.os_family == "windows" else r"[a-z_][a-z0-9_.-]{0,31}"
        if set(parameters) - allowed or not re.fullmatch(username_pattern, str(parameters.get("username", ""))):
            raise HTTPException(status_code=422, detail="Invalid user creation parameters")
        password = str(parameters.get("password", ""))
        groups = parameters.get("groups", [])
        if not 12 <= len(password) <= 1024 or any(value in password for value in ("\n", "\r", ":")) or not isinstance(groups, list) or len(groups) > 100 or any(not isinstance(group, str) or not re.fullmatch(r"[A-Za-z0-9_.@ -]{1,128}", group) for group in groups) or len(groups) != len(set(groups)):
            raise HTTPException(status_code=422, detail="Password or group selection is invalid")
        return
    if action == "user.update":
        allowed = {"username", "password", "groups", "is_admin", "enabled", "account_expires", "max_password_days"}
        groups = parameters.get("groups", [])
        if set(parameters) - allowed or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", str(parameters.get("username", ""))) or not isinstance(groups, list) or len(groups) > 100 or any(not isinstance(group, str) or not re.fullmatch(r"[A-Za-z0-9_.@ -]{1,128}", group) for group in groups) or len(groups) != len(set(groups)):
            raise HTTPException(status_code=422, detail="Invalid user update parameters")
        password = str(parameters.get("password", ""))
        if password and (not 12 <= len(password) <= 1024 or any(value in password for value in ("\n", "\r", ":"))):
            raise HTTPException(status_code=422, detail="New password must contain at least 12 characters")
        if parameters.get("account_expires") and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(parameters["account_expires"])):
            raise HTTPException(status_code=422, detail="Invalid account expiration date")
        if "max_password_days" in parameters and (server.os_family == "windows" or isinstance(parameters["max_password_days"], bool) or not isinstance(parameters["max_password_days"], int) or not -1 <= parameters["max_password_days"] <= 99999):
            raise HTTPException(status_code=422, detail="Invalid maximum password age")
        return
    if action == "user.delete":
        names = parameters.get("usernames", [])
        if set(parameters) != {"usernames"} or not isinstance(names, list) or not 1 <= len(names) <= 50:
            raise HTTPException(status_code=422, detail="Select between 1 and 50 users")
        return
    if action == "group.create":
        group_pattern = r"[A-Za-z0-9_.@ -]{1,128}" if server.os_family == "windows" else r"[a-z_][a-z0-9_.-]{0,31}"
        if set(parameters) != {"group"} or not re.fullmatch(group_pattern, str(parameters.get("group", ""))):
            raise HTTPException(status_code=422, detail="Invalid group name")
        return
    if action == "group.delete":
        groups = parameters.get("groups", [])
        if set(parameters) != {"groups"} or not isinstance(groups, list) or not 1 <= len(groups) <= 50 or any(not isinstance(group, str) or not re.fullmatch(r"[A-Za-z0-9_.@ -]{1,128}", group) for group in groups) or len(groups) != len(set(groups)):
            raise HTTPException(status_code=422, detail="Select between 1 and 50 groups")
        return
    if action == "process.kill":
        processes = parameters.get("processes", [])
        if set(parameters) != {"processes"} or not isinstance(processes, list) or not 1 <= len(processes) <= 100 or any(not isinstance(item, dict) or set(item) != {"pid", "name", "created"} or isinstance(item.get("pid"), bool) or not isinstance(item.get("pid"), int) or item["pid"] <= 2 or not isinstance(item.get("name"), str) or not 1 <= len(item["name"]) <= 512 or any(ord(character) < 32 for character in item["name"]) or isinstance(item.get("created"), bool) or not isinstance(item.get("created"), (int, float)) for item in processes):
            raise HTTPException(status_code=422, detail="Select between 1 and 100 processes")
        return
    if action == "patch.install":
        updates = parameters.get("updates", [])
        if set(parameters) != {"updates"} or not isinstance(updates, list) or not 1 <= len(updates) <= 100 or any(not isinstance(item, dict) or set(item) - {"id", "version", "revision"} or not isinstance(item.get("id"), str) or not 1 <= len(item["id"]) <= 300 or not isinstance(item.get("version", ""), str) or len(item.get("version", "")) > 300 or ("revision" in item and (isinstance(item["revision"], bool) or not isinstance(item["revision"], int))) for item in updates):
            raise HTTPException(status_code=422, detail="Select between 1 and 100 updates")
        return
    if action in {"storage.extend", "storage.shrink", "storage.create", "storage.delete"}:
        kind = str(parameters.get("kind", ""))
        if action == "storage.shrink":
            allowed_kinds = {"windows_partition"} if server.os_family == "windows" else set()
        else:
            allowed_kinds = {"windows_partition"} if server.os_family == "windows" else ({"linux_partition", "linux_lv"} if action == "storage.extend" else {"linux_partition", "linux_lv", "linux_vg"})
        if kind not in allowed_kinds:
            raise HTTPException(status_code=422, detail="Storage target does not match the server operating system")
        schemas: dict[tuple[str, str], tuple[set[str], set[str]]] = {
            ("storage.extend", "windows_partition"): ({"kind", "disk_number", "partition_number", "add_bytes"}, set()),
            ("storage.shrink", "windows_partition"): ({"kind", "disk_number", "partition_number", "shrink_bytes"}, set()),
            ("storage.extend", "linux_partition"): ({"kind", "path", "add_bytes"}, set()),
            ("storage.extend", "linux_lv"): ({"kind", "path", "add_bytes"}, set()),
            ("storage.create", "windows_partition"): ({"kind", "disk_number", "size_bytes", "filesystem", "label"}, {"drive_letter"}),
            ("storage.create", "linux_partition"): ({"kind", "disk", "start_bytes", "size_bytes", "filesystem"}, {"label", "mount_point"}),
            ("storage.create", "linux_lv"): ({"kind", "vg_name", "name", "size_bytes"}, {"filesystem", "label", "mount_point"}),
            ("storage.create", "linux_vg"): ({"kind", "device", "name", "size_bytes"}, set()),
            ("storage.delete", "windows_partition"): ({"kind", "disk_number", "partition_number"}, set()),
            ("storage.delete", "linux_partition"): ({"kind", "path"}, set()),
            ("storage.delete", "linux_lv"): ({"kind", "path"}, set()),
            ("storage.delete", "linux_vg"): ({"kind", "name"}, set()),
        }
        required, optional = schemas[(action, kind)]
        if not required.issubset(parameters) or set(parameters) - required - optional:
            raise HTTPException(status_code=422, detail="Storage parameters are incomplete or unsupported")
        numeric = [key for key in ("add_bytes", "shrink_bytes", "size_bytes") if key in parameters]
        numeric += [key for key in ("disk_number", "partition_number", "start_bytes") if key in parameters]
        if any(isinstance(parameters[key], bool) or not isinstance(parameters[key], int) or parameters[key] < (1 if key in {"add_bytes", "shrink_bytes", "size_bytes", "partition_number"} else 0) for key in numeric):
            raise HTTPException(status_code=422, detail="Storage size must be a positive byte value")
        if any(not isinstance(value, str) or len(value) > 256 or any(ord(character) < 32 for character in value) for key, value in parameters.items() if key not in numeric and key != "kind"):
            raise HTTPException(status_code=422, detail="Storage text parameters are invalid")
        return
    if action == "logs.read":
        sources = parameters.get("sources", [])
        if set(parameters) != {"limit", "sources"} or parameters.get("limit") != 500 or not isinstance(sources, list) or not 1 <= len(sources) <= 20:
            raise HTTPException(status_code=422, detail="Invalid log read request")
        return
    # Existing compatibility actions are still revalidated by the Agent.


async def mark_tunnel_closed(session_id: str, reason: str) -> None:
    factory = SessionLocal
    if factory is None:
        return
    with factory() as db:
        session = db.get(RemoteSession, session_id)
        if session and session.status not in {"closed", "failed"}:
            session.status = "closed" if reason == "closed" else "failed"
            session.finished_at = now()
            audit(db, "system:tunnel", "session.tunnel.closed", session_id, result=session.status, detail={"reason": reason})
            db.commit()


tunnel_hub = TunnelHub(
    bind_host=settings.tunnel_bind_host,
    listener_ttl_seconds=settings.tunnel_listener_ttl_seconds,
    connect_timeout_seconds=settings.tunnel_connect_timeout_seconds,
    max_sessions_per_agent=settings.tunnel_max_sessions_per_agent,
    closed_callback=mark_tunnel_closed,
)


app = FastAPI(
    title="Trạm Vận Hành API",
    version=RELEASE_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
origins = [item.strip() for item in settings.allowed_origins.split(",") if item.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
allowed_hosts = [item.strip() for item in settings.allowed_hosts.split(",") if item.strip()]
if allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)


@app.middleware("http")
async def add_api_security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


def build_database_url(payload: DatabaseSetupRequest) -> str:
    return URL.create(
        drivername="postgresql+psycopg",
        username=payload.username,
        password=payload.password,
        host=payload.host,
        port=payload.port,
        database=payload.database,
        query={"sslmode": payload.sslmode},
    ).render_as_string(hide_password=False)


def save_bootstrap_config(database_url: str, jwt_secret: str, job_secret_key: str) -> None:
    bootstrap_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = bootstrap_path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"database_url": database_url, "jwt_secret": jwt_secret, "job_secret_key": job_secret_key}, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(bootstrap_path)


def activate_database(database_url: str, *, initialize_schema: bool = True) -> Engine:
    global engine, SessionLocal, database_error
    candidate = engine if engine is not None and database_url == settings.database_url else create_engine(database_url, pool_pre_ping=True)
    try:
        with candidate.connect() as connection:
            connection.execute(text("SELECT 1"))
        if initialize_schema:
            Base.metadata.create_all(candidate)
    except Exception as exc:
        if candidate is not engine:
            candidate.dispose()
        database_error = type(exc).__name__
        raise
    with database_lock:
        previous = engine
        engine = candidate
        SessionLocal = sessionmaker(bind=candidate, expire_on_commit=False)
        settings.database_url = database_url
        database_error = ""
        if previous is not None and previous is not candidate:
            previous.dispose()
    return candidate


def database_state() -> dict[str, Any]:
    configured = bool(settings.database_url)
    connected = False
    schema_ready = False
    admin_exists = False
    dashboard_url = ""
    factory = SessionLocal
    if configured and engine is not None and factory is not None:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            with factory() as db:
                schema_ready = inspect(engine).has_table("users") and inspect(engine).has_table("system_settings")
                if schema_ready:
                    admin_exists = db.execute(select(User).where(User.role == "admin", User.enabled.is_(True)).limit(1)).scalar_one_or_none() is not None
                    setting = db.get(SystemSetting, "dashboard_url")
                    dashboard_url = setting.value if setting else ""
            connected = True
        except Exception:
            connected = False
    secrets_ready = bool(settings.jwt_secret and settings.job_secret_key)
    required = not (connected and schema_ready and admin_exists and dashboard_url and secrets_ready)
    return {
        "setupRequired": required,
        "databaseConfigured": configured,
        "databaseConnected": connected,
        "schemaReady": schema_ready,
        "adminExists": admin_exists,
        "secretsReady": secrets_ready,
        "dashboardUrl": dashboard_url,
        "setupTokenRequired": bool(settings.setup_token),
        "status": "ready" if not required else "setup_required",
    }


def db_session():
    factory = SessionLocal
    if factory is None:
        raise HTTPException(status_code=503, detail="Database setup is required")
    session = factory()
    try:
        yield session
    finally:
        session.close()


def now() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def job_fernet() -> Fernet:
    try:
        return Fernet(settings.job_secret_key.encode())
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=503, detail="Job parameter encryption is not configured") from exc


def protect_parameters(value: Any, key_name: str = "") -> Any:
    if isinstance(value, dict):
        return {key: protect_parameters(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [protect_parameters(item, key_name) for item in value]
    if key_name.lower() in {"password", "secret", "token", "private_key"} and value not in {None, ""}:
        return {"__tram_encrypted__": job_fernet().encrypt(str(value).encode()).decode()}
    return value


def reveal_parameters(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"__tram_encrypted__"}:
        try:
            return job_fernet().decrypt(value["__tram_encrypted__"].encode()).decode()
        except InvalidToken as exc:
            raise HTTPException(status_code=500, detail="Encrypted job parameter cannot be decrypted") from exc
    if isinstance(value, dict):
        return {key: reveal_parameters(item) for key, item in value.items()}
    if isinstance(value, list):
        return [reveal_parameters(item) for item in value]
    return value


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")


def auth_throttle_key(scope: str, value: str) -> str:
    secret = settings.jwt_secret.encode() if settings.jwt_secret else b"tram-auth-throttle-unconfigured"
    return hmac.new(secret, f"{scope}\0{value}".encode(), hashlib.sha256).hexdigest()


def auth_throttle_scopes(request: Request, identity: str) -> list[tuple[str, int]]:
    source = client_ip(request) or "unknown"
    normalized_identity = identity.strip().lower()
    return [
        (auth_throttle_key("ip", source), settings.auth_ip_failures),
        (auth_throttle_key("identity-ip", f"{normalized_identity}\0{source}"), settings.auth_account_failures),
    ]


def enforce_auth_throttle(db: Session, scopes: list[tuple[str, int]]) -> None:
    timestamp = now()
    blocked_until = max(
        (
            aware(row.blocked_until)
            for key_hash, _ in scopes
            if (row := db.get(AuthThrottle, key_hash)) is not None and aware(row.blocked_until) is not None
        ),
        default=None,
    )
    if blocked_until is not None and blocked_until > timestamp:
        retry_after = max(1, int((blocked_until - timestamp).total_seconds()))
        raise HTTPException(
            status_code=429,
            detail="Đăng nhập tạm thời bị giới hạn do quá nhiều lần thử thất bại",
            headers={"Retry-After": str(retry_after)},
        )


def record_auth_failure(db: Session, scopes: list[tuple[str, int]]) -> None:
    timestamp = now()
    window = timedelta(seconds=settings.auth_window_seconds)
    for key_hash, limit in scopes:
        row = db.get(AuthThrottle, key_hash)
        if row is None:
            row = AuthThrottle(key_hash=key_hash, failures=0, window_started_at=timestamp, updated_at=timestamp)
            db.add(row)
        started = aware(row.window_started_at) or timestamp
        if timestamp - started >= window:
            row.failures = 0
            row.window_started_at = timestamp
            row.blocked_until = None
        row.failures += 1
        row.updated_at = timestamp
        if row.failures >= limit:
            row.blocked_until = timestamp + timedelta(seconds=settings.auth_lockout_seconds)


def clear_auth_throttle(db: Session, scopes: list[tuple[str, int]]) -> None:
    keys = [key_hash for key_hash, _ in scopes]
    if keys:
        db.execute(delete(AuthThrottle).where(AuthThrottle.key_hash.in_(keys)))


def prune_auth_throttles(db: Session) -> None:
    db.execute(delete(AuthThrottle).where(AuthThrottle.updated_at < now() - timedelta(days=1)))


def audit(db: Session, actor: str, action: str, target: str, request: Request | None = None, result: str = "success", detail: dict[str, Any] | None = None) -> None:
    previous = db.execute(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(1)).scalar_one_or_none()
    occurred = now()
    payload = json.dumps({"occurred_at": occurred.isoformat(), "actor": actor, "action": action, "target": target, "result": result, "detail": detail or {}}, sort_keys=True, separators=(",", ":"))
    previous_hash = previous.event_hash if previous else "0" * 64
    event_hash = hashlib.sha256((previous_hash + payload).encode()).hexdigest()
    db.add(AuditEvent(occurred_at=occurred, actor=actor, action=action, target=target, result=result, source_ip=client_ip(request) if request else "", detail=detail or {}, previous_hash=previous_hash, event_hash=event_hash))


def prune_audit_events(db: Session) -> int:
    """Delete expired audit rows while preserving a durable hash-chain anchor."""
    cutoff = now() - timedelta(days=settings.audit_retention_days)
    expired_count = int(
        db.execute(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.occurred_at < cutoff)
        ).scalar_one()
    )
    if expired_count == 0:
        return 0
    newest_expired = db.execute(
        select(AuditEvent)
        .where(AuditEvent.occurred_at < cutoff)
        .order_by(AuditEvent.occurred_at.desc())
        .limit(1)
    ).scalar_one()
    anchor = {
        "cutoff": cutoff.isoformat(),
        "deletedCount": expired_count,
        "lastDeletedHash": newest_expired.event_hash,
        "lastDeletedOccurredAt": aware(newest_expired.occurred_at).isoformat(),
        "retentionDays": settings.audit_retention_days,
    }
    db.execute(
        delete(AuditEvent)
        .where(AuditEvent.occurred_at < cutoff)
        .execution_options(synchronize_session=False)
    )
    db.merge(SystemSetting(key="audit_retention_anchor", value=json.dumps(anchor, sort_keys=True, separators=(",", ":"))))
    audit(
        db,
        "system:audit-retention",
        "audit.retention.pruned",
        "audit-events",
        detail=anchor,
    )
    return expired_count


RECORDING_RETENTION_KEY = "recording_retention"
RECORDING_RETENTION_STATUS_KEY = "recording_retention_status"


def read_recording_retention(db: Session) -> dict[str, Any]:
    result: dict[str, Any] = {"enabled": True, "days": 180}
    setting = db.get(SystemSetting, RECORDING_RETENTION_KEY)
    if setting:
        try:
            parsed = json.loads(setting.value)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("enabled"), bool):
                    result["enabled"] = parsed["enabled"]
                days = parsed.get("days")
                if isinstance(days, int) and not isinstance(days, bool) and 30 <= days <= 3650:
                    result["days"] = days
        except (TypeError, ValueError):
            pass
    status = db.get(SystemSetting, RECORDING_RETENTION_STATUS_KEY)
    if status:
        try:
            parsed_status = json.loads(status.value)
            if isinstance(parsed_status, dict):
                result["lastRun"] = parsed_status
        except (TypeError, ValueError):
            pass
    return result


def recording_session_id_from_name(name: str) -> str | None:
    if len(name) < 36:
        return None
    session_id = name[:36]
    try:
        parsed = uuid.UUID(session_id)
    except ValueError:
        return None
    if str(parsed) != session_id.lower() or (len(name) > 36 and name[36] not in "-._"):
        return None
    return session_id


def prune_recording_files(db: Session) -> dict[str, Any]:
    config = read_recording_retention(db)
    timestamp = now()
    result: dict[str, Any] = {
        "ranAt": timestamp.isoformat(),
        "enabled": bool(config["enabled"]),
        "days": int(config["days"]),
        "deletedFiles": 0,
        "deletedBytes": 0,
        "errors": 0,
    }
    if not config["enabled"]:
        return result
    cutoff = timestamp - timedelta(days=int(config["days"]))
    result["cutoff"] = cutoff.isoformat()
    try:
        root = Path(settings.recording_root).resolve(strict=True)
        if not root.is_dir():
            raise OSError("recording root is not a directory")
        candidates = list(root.iterdir())
    except (OSError, RuntimeError) as exc:
        result["errors"] = 1
        result["error"] = str(exc)[:500]
        db.merge(SystemSetting(key=RECORDING_RETENTION_STATUS_KEY, value=json.dumps(result, separators=(",", ":"))))
        return result
    active_session_ids = set(db.execute(select(RemoteSession.id).where(RemoteSession.status.not_in({"closed", "failed"}))).scalars().all())
    for candidate in candidates:
        session_id = recording_session_id_from_name(candidate.name)
        if not session_id or session_id in active_session_ids or candidate.is_symlink():
            continue
        try:
            resolved = candidate.resolve(strict=True)
            stat = resolved.stat()
            if resolved.parent != root or not resolved.is_file() or datetime.fromtimestamp(stat.st_mtime, UTC) >= cutoff:
                continue
            resolved.unlink()
            result["deletedFiles"] += 1
            result["deletedBytes"] += stat.st_size
        except OSError:
            result["errors"] += 1
    db.merge(SystemSetting(key=RECORDING_RETENTION_STATUS_KEY, value=json.dumps(result, separators=(",", ":"))))
    if result["deletedFiles"] or result["errors"]:
        audit(
            db,
            "system:recording-retention",
            "session.recording.retention.pruned",
            "recordings",
            result="success" if not result["errors"] else "partial",
            detail={key: value for key, value in result.items() if key != "enabled"},
        )
    return result


def issue_jwt(user: User) -> str:
    timestamp = now()
    return jwt.encode({"sub": user.id, "username": user.username, "role": user.role, "iss": settings.jwt_issuer, "iat": timestamp, "exp": timestamp + timedelta(minutes=settings.jwt_ttl_minutes)}, settings.jwt_secret, algorithm="HS256")


def issue_mfa_challenge(user: User) -> str:
    timestamp = now()
    return jwt.encode({"sub": user.id, "purpose": "mfa", "iss": settings.jwt_issuer, "iat": timestamp, "exp": timestamp + timedelta(minutes=5)}, settings.jwt_secret, algorithm="HS256")


def mfa_login_response(db: Session, user: User) -> dict[str, Any]:
    credential = db.get(MFACredential, user.id)
    if credential is None:
        secret = pyotp.random_base32()
        credential = MFACredential(user_id=user.id, secret_encrypted=job_fernet().encrypt(secret.encode()).decode())
        db.add(credential)
        db.flush()
    else:
        try:
            secret = job_fernet().decrypt(credential.secret_encrypted.encode()).decode()
        except InvalidToken as exc:
            raise HTTPException(status_code=503, detail="Không thể đọc cấu hình MFA") from exc
    response: dict[str, Any] = {"mfa_required": True, "setup_required": not credential.enrolled, "challenge_token": issue_mfa_challenge(user), "user": {"username": user.username, "displayName": user.display_name, "role": user.role}}
    if not credential.enrolled:
        uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="Trạm Vận Hành")
        image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        stream = io.BytesIO()
        image.save(stream)
        response.update({"provisioning_uri": uri, "qr_svg": "data:image/svg+xml;base64," + base64.b64encode(stream.getvalue()).decode()})
    return response


def read_ldap_config(db: Session, include_secret: bool = False) -> dict[str, Any]:
    setting = db.get(SystemSetting, "ldap_config")
    if not setting or not setting.value:
        return {"enabled": False}
    try:
        config = json.loads(setting.value)
    except (TypeError, ValueError):
        return {"enabled": False}
    encrypted = config.pop("bind_password_encrypted", "")
    if include_secret and encrypted:
        try:
            config["bind_password"] = job_fernet().decrypt(encrypted.encode()).decode()
        except InvalidToken as exc:
            raise HTTPException(status_code=503, detail="Không thể đọc mật khẩu LDAP") from exc
    config["password_configured"] = bool(encrypted)
    return config


def authenticate_ldap(db: Session, username: str, password: str) -> User | None:
    config = read_ldap_config(db, include_secret=True)
    if not config.get("enabled"):
        raise HTTPException(status_code=503, detail="Đăng nhập Domain chưa được cấu hình")
    if not username or not password:
        return None
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=config.get("ca_certificate") or None) if config.get("use_ssl", True) else None
    ldap_server = LDAPServer(config["host"], port=int(config.get("port", 636)), use_ssl=bool(config.get("use_ssl", True)), tls=tls, get_info=ALL, connect_timeout=8)
    try:
        with Connection(ldap_server, user=config.get("bind_dn") or None, password=config.get("bind_password") or None, auto_bind=True, receive_timeout=10) as service:
            attribute = config.get("user_attribute", "sAMAccountName")
            allowed_group_dns = [str(value).strip() for value in config.get("allowed_group_dns", []) if str(value).strip()]
            membership_filter = ""
            if allowed_group_dns:
                # AD's matching-rule-in-chain includes direct and nested group
                # membership, so adding a user to an approved operations group
                # is sufficient without opening login to the whole directory.
                clauses = "".join(f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)})" for group_dn in allowed_group_dns)
                membership_filter = f"(|{clauses})"
            user_filter = f"({attribute}={escape_filter_chars(username)})"
            search_filter = f"(&{user_filter}{membership_filter})" if membership_filter else user_filter
            service.search(config["base_dn"], search_filter, search_scope=SUBTREE, attributes=[config.get("display_attribute", "displayName")], size_limit=2)
            if len(service.entries) != 1:
                return None
            entry = service.entries[0]
            user_dn = entry.entry_dn
            display_value = getattr(entry, config.get("display_attribute", "displayName"), None)
            display_name = str(display_value.value) if display_value and display_value.value else username
        with Connection(ldap_server, user=user_dn, password=password, auto_bind=True, receive_timeout=10):
            pass
    except Exception:
        return None
    canonical = f"{config.get('domain_label', 'DOMAIN')}\\{username}"
    if len(canonical) > 80:
        return None
    user = db.execute(select(User).where(User.username == canonical)).scalar_one_or_none()
    if user is None:
        default_role = str(config.get("default_role", "viewer"))
        if db.get(PlatformRole, default_role) is None:
            default_role = "viewer"
        user = User(username=canonical, password_hash="!LDAP", display_name=display_name, role=default_role)
        db.add(user)
        db.flush()
    else:
        user.display_name = display_name
    return user


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(db_session)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        claims = jwt.decode(authorization[7:], settings.jwt_secret, algorithms=["HS256"], issuer=settings.jwt_issuer)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid session") from exc
    user = db.get(User, claims.get("sub"))
    if not user or not user.enabled:
        raise HTTPException(status_code=401, detail="User disabled")
    return user


def ensure_builtin_roles(db: Session) -> None:
    for name, definition in BUILTIN_ROLE_DEFINITIONS.items():
        role = db.get(PlatformRole, name)
        if role is None:
            db.add(PlatformRole(name=name, display_name=definition["display_name"], description=definition["description"], permissions=definition["permissions"], system=True))
            continue
        role.display_name = definition["display_name"]
        role.description = definition["description"]
        role.permissions = definition["permissions"]
        role.system = True


def platform_role_permissions(db: Session, role_name: str) -> set[str]:
    role = db.get(PlatformRole, role_name)
    if role is not None:
        return {str(permission) for permission in role.permissions or [] if permission in PERMISSION_CATALOG}
    fallback = BUILTIN_ROLE_DEFINITIONS.get(role_name, {})
    return set(fallback.get("permissions", []))


def validate_platform_role(db: Session, role_name: str, *, ldap_default: bool = False) -> PlatformRole:
    role = db.get(PlatformRole, role_name)
    if role is None and role_name in BUILTIN_ROLE_DEFINITIONS:
        ensure_builtin_roles(db)
        db.flush()
        role = db.get(PlatformRole, role_name)
    if role is None:
        raise HTTPException(status_code=422, detail="Role không tồn tại")
    if ldap_default and role.name == "admin":
        raise HTTPException(status_code=422, detail="Role mặc định LDAP không được là admin; hãy gán admin riêng cho từng user sau lần đăng nhập đầu tiên")
    return role


def normalize_permissions(values: list[str]) -> list[str]:
    normalized = list(dict.fromkeys(values))
    unknown = sorted(set(normalized) - ALL_PLATFORM_PERMISSIONS)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Permission không hợp lệ: {', '.join(unknown)}")
    return sorted(normalized)


def platform_role_json(role: PlatformRole) -> dict[str, Any]:
    return {"name": role.name, "displayName": role.display_name, "description": role.description, "permissions": sorted(role.permissions or []), "system": role.system, "createdAt": aware(role.created_at).isoformat(), "updatedAt": aware(role.updated_at).isoformat()}


def require_permission(permission: str):
    if permission not in PERMISSION_CATALOG:
        raise RuntimeError(f"Unknown platform permission: {permission}")

    def dependency(user: User = Depends(current_user), db: Session = Depends(db_session)) -> User:
        if permission not in platform_role_permissions(db, user.role):
            raise HTTPException(status_code=403, detail="Role hiện tại không có quyền thực hiện chức năng này")
        return user
    return dependency


def verify_agent_identity(headers: Mapping[str, str], method: str, path: str, db: Session, agent_id: str, body: bytes) -> Server:
    try:
        certificate = x509.load_der_x509_certificate(base64.b64decode(headers.get("x-tram-agent-certificate", ""), validate=True))
        timestamp = int(headers.get("x-tram-agent-timestamp", ""))
        signature = base64.b64decode(headers.get("x-tram-agent-signature", ""), validate=True)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Signed agent identity is required") from None
    if abs(int(now().timestamp()) - timestamp) > 300:
        raise HTTPException(status_code=401, detail="Agent request timestamp is outside the allowed window")
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    server = db.get(Server, agent_id)
    if not server or not server.cert_fingerprint or not hmac.compare_digest(server.cert_fingerprint, fingerprint):
        raise HTTPException(status_code=401, detail="Unknown agent certificate")
    if db.get(ServerRetirement, agent_id) is not None or server.status == "retired":
        raise HTTPException(status_code=403, detail="Agent was removed by an Administrator")
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != agent_id:
        raise HTTPException(status_code=401, detail="Certificate subject mismatch")
    if aware(certificate.not_valid_after_utc) < now() or aware(certificate.not_valid_before_utc) > now():
        raise HTTPException(status_code=401, detail="Agent certificate is not currently valid")
    if server.status == "quarantined":
        raise HTTPException(status_code=403, detail="Agent is quarantined")
    message = f"{timestamp}\n{method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise HTTPException(status_code=401, detail="Unsupported agent certificate key")
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise HTTPException(status_code=401, detail="Invalid agent request signature") from None
    return server


def verify_agent(request: Request, db: Session, agent_id: str, body: bytes) -> Server:
    return verify_agent_identity(request.headers, request.method, request.url.path, db, agent_id, body)


def classify_os(inv: Inventory) -> tuple[str, str]:
    family = inv.os_family
    combined = f"{inv.os_name} {inv.distribution_id}".lower()
    if family == "windows" and "windows" not in combined:
        raise HTTPException(status_code=400, detail="Windows inventory is inconsistent")
    if family == "linux" and not inv.distribution_id:
        raise HTTPException(status_code=400, detail="Linux distribution ID is required")
    if family == "linux" and inv.distribution_id not in {"ubuntu", "ol", "oracle", "oraclelinux", "rhel", "centos", "rocky", "almalinux", "debian"}:
        return family, "unverified"
    return family, "verified"


def server_json(server: Server) -> dict[str, Any]:
    last_seen = aware(server.last_seen)
    age = (now() - last_seen).total_seconds() if last_seen else 10**9
    health = "offline" if age > 180 else "critical" if server.alerts >= 3 or server.disk_percent >= 95 else "warning" if server.alerts or server.disk_percent >= 85 or server.pending_updates >= 20 else "healthy"
    relative = "Chưa kết nối" if not last_seen else f"{int(age)} giây trước" if age < 60 else f"{int(age // 60)} phút trước"
    days, remainder = divmod(server.uptime_seconds, 86400)
    hours = remainder // 3600
    return {"id": server.id, "name": server.name, "osFamily": server.os_family, "os": server.os_name, "version": server.os_version, "address": server.address, "environment": server.environment, "health": health, "agentVersion": server.agent_version, "lastSeen": relative, "cpu": round(server.cpu_percent), "memory": round(server.memory_percent), "disk": round(server.disk_percent), "uptime": f"{days} ngày {hours} giờ", "updates": server.pending_updates, "alerts": server.alerts, "services": server.services_running, "owner": server.owner, "tags": server.tags or [], "verifiedOS": server.verified_os, "tunnelOnline": tunnel_hub.is_online(server.id)}


def sign_agent_csr(csr_pem: str, agent_id: str) -> tuple[str, str, datetime]:
    try:
        ca_cert = x509.load_pem_x509_certificate(Path(settings.agent_ca_cert).read_bytes())
        ca_key = serialization.load_pem_private_key(Path(settings.agent_ca_key).read_bytes(), password=None)
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=503, detail="Agent CA is unavailable") from exc
    if not csr.is_signature_valid:
        raise HTTPException(status_code=400, detail="Invalid CSR signature")
    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names or common_names[0].value != agent_id:
        raise HTTPException(status_code=400, detail="CSR common name must equal agent_id")
    expires = now() + timedelta(days=settings.agent_cert_days)
    cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=5)).not_valid_after(expires).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False).add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"spiffe://tram-ops/agent/{agent_id}")]), critical=False).sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return pem, fingerprint, expires


def encrypt_guacamole_json(payload: dict[str, Any]) -> str:
    key_hex = settings.guacamole_json_secret
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key_hex):
        raise HTTPException(status_code=503, detail="Guacamole JSON secret is not configured")
    key = bytes.fromhex(key_hex)
    body = json.dumps(payload, separators=(",", ":")).encode()
    signed = hmac.new(key, body, hashlib.sha256).digest() + body
    padder = padding.PKCS7(128).padder()
    padded = padder.update(signed) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()


def guacamole_launch_url(base_url: str, connection_identifier: str, encrypted_data: str) -> str:
    """Return a Guacamole client route authenticated by encrypted JSON data."""
    client_identifier = base64.urlsafe_b64encode(
        f"{connection_identifier}\0c\0json".encode("utf-8")
    ).decode("ascii").rstrip("=")
    return (
        f"{base_url.rstrip('/')}/#/client/{client_identifier}"
        f"?data={quote(encrypted_data, safe='')}"
    )


SSH_HOST_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}


def guacamole_ssh_host_key(address: str, port: int, public_key: str | None) -> str | None:
    """Return the host key as the single known_hosts entry Guacamole requires."""
    if not public_key:
        return None
    if not address or any(character.isspace() for character in address):
        raise HTTPException(status_code=409, detail="Địa chỉ SSH trong inventory không hợp lệ")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=409, detail="Cổng SSH relay không hợp lệ")

    parts = public_key.strip().split()
    key_index = 0 if len(parts) >= 2 and parts[0] in SSH_HOST_KEY_TYPES else 1 if len(parts) >= 3 and parts[1] in SSH_HOST_KEY_TYPES else -1
    if key_index < 0:
        raise HTTPException(status_code=409, detail="SSH host key trong inventory không đúng định dạng OpenSSH")

    key_type, encoded_key = parts[key_index], parts[key_index + 1]
    try:
        decoded_key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=409, detail="SSH host key trong inventory không hợp lệ") from exc
    if len(decoded_key) < 16:
        raise HTTPException(status_code=409, detail="SSH host key trong inventory quá ngắn")

    # The agent reads an OpenSSH .pub file, which contains only KEY_TYPE KEY.
    # Guacamole's host-key parameter instead requires a complete known_hosts
    # entry. OpenSSH scopes non-default ports as [HOST]:PORT, and every reverse
    # tunnel listener uses a dynamic non-default port.
    known_hosts_address = address if port == 22 else f"[{address}]:{port}"
    return f"{known_hosts_address} {key_type} {encoded_key}"


def guacamole_rdp_certificate_fingerprint(value: object) -> str | None:
    """Return an RDP certificate pin in the format expected by FreeRDP."""
    fingerprint = str(value or "").strip().lower()
    match = re.fullmatch(r"(sha1|sha256):?((?:[0-9a-f]{2}:?){20,32})", fingerprint)
    if not match:
        return None
    algorithm, digest = match.groups()
    digest = digest.replace(":", "")
    expected_length = 40 if algorithm == "sha1" else 64
    if len(digest) != expected_length:
        return None
    # FreeRDP 2.x compares against the colon-separated representation returned
    # by OpenSSL. FreeRDP 3.x accepts both separated and compact forms. Always
    # emit the representation that works with both versions.
    separated = ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))
    return f"{algorithm}:{separated}"


def expire_file_payloads(db: Session) -> int:
    cutoff = now() - timedelta(hours=settings.file_transfer_ttl_hours)
    transfers = db.execute(
        select(FileTransfer).where(
            FileTransfer.created_at < cutoff,
            FileTransfer.content_encrypted.is_not(None),
            FileTransfer.status.in_({"pending_approval", "queued", "transferring"}),
        )
    ).scalars().all()
    for transfer in transfers:
        transfer.status = "expired"
        transfer.content_encrypted = None
        transfer.nonce = ""
        if transfer.job_id:
            job = db.get(Job, transfer.job_id)
            if job and job.status in {"pending_approval", "queued", "dispatched"}:
                job.status = "expired"
                job.finished_at = now()
        audit(db, "system:file-retention", "file.payload.expired", transfer.id, result="expired", detail={"server_id": transfer.server_id, "sha256": transfer.sha256})
    return len(transfers)


def retire_legacy_pending_jobs(db: Session) -> int:
    jobs = db.execute(select(Job).where(Job.status == "pending_approval")).scalars().all()
    for job in jobs:
        job.status = "cancelled"
        job.finished_at = now()
        if not job.output:
            job.output = "Job cũ đã bị hủy khi hệ thống chuyển sang thực thi trực tiếp; hãy tạo lại thao tác nếu vẫn cần."
        transfer = db.execute(select(FileTransfer).where(FileTransfer.job_id == job.id)).scalar_one_or_none()
        if transfer and transfer.status == "pending_approval":
            transfer.status = "cancelled"
            transfer.content_encrypted = None
            transfer.nonce = ""
        audit(
            db,
            "system:direct-execution-migration",
            "job.legacy_pending.cancelled",
            job.id,
            result="cancelled",
            detail={"server_id": job.server_id, "action": job.action},
        )
    return len(jobs)


@app.on_event("startup")
def startup() -> None:
    if not settings.database_url:
        return
    try:
        activate_database(settings.database_url)
        factory = SessionLocal
        if factory is None:
            return
        with factory() as db:
            ensure_builtin_roles(db)
            retire_legacy_pending_jobs(db)
            expire_file_payloads(db)
            prune_audit_events(db)
            prune_recording_files(db)
            exists = db.execute(select(User).limit(1)).scalar_one_or_none()
            if not exists and settings.bootstrap_admin_password:
                if len(settings.bootstrap_admin_password) < 14:
                    raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 14 characters")
                db.add(User(username=settings.bootstrap_admin_user, display_name="Platform Administrator", password_hash=password_hasher.hash(settings.bootstrap_admin_password), role="admin"))
            if settings.dashboard_url:
                db.merge(SystemSetting(key="dashboard_url", value=settings.dashboard_url.strip().rstrip("/")))
            db.commit()
    except Exception:
        # The API remains available in setup mode so an operator can repair the
        # connection from the first-run wizard.
        return


audit_retention_task: asyncio.Task[None] | None = None
recording_retention_task: asyncio.Task[None] | None = None


async def audit_retention_loop() -> None:
    while True:
        await asyncio.sleep(3600)
        factory = SessionLocal
        if factory is None:
            continue
        try:
            with factory() as db:
                prune_audit_events(db)
                db.commit()
        except Exception:
            # Retention must never make the API unavailable. The next hourly
            # cycle and the next application startup retry the cleanup.
            continue


async def recording_retention_loop() -> None:
    while True:
        await asyncio.sleep(21600)
        factory = SessionLocal
        if factory is None:
            continue
        try:
            with factory() as db:
                prune_recording_files(db)
                db.commit()
        except Exception:
            # A failed cleanup must not stop remote administration. The next
            # six-hour cycle retries and keeps a durable status when possible.
            continue


@app.on_event("startup")
async def start_audit_retention() -> None:
    global audit_retention_task, recording_retention_task
    if audit_retention_task is None or audit_retention_task.done():
        audit_retention_task = asyncio.create_task(audit_retention_loop())
    if recording_retention_task is None or recording_retention_task.done():
        recording_retention_task = asyncio.create_task(recording_retention_loop())


@app.on_event("shutdown")
async def stop_audit_retention() -> None:
    global audit_retention_task, recording_retention_task
    for task in (audit_retention_task, recording_retention_task):
        if task is None:
            continue
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    audit_retention_task = None
    recording_retention_task = None


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    state = database_state()
    return {"status": "ok" if not state["setupRequired"] else "setup_required"}


@app.get("/api/v1/setup/status")
def setup_status() -> dict[str, Any]:
    state = database_state()
    return {
        "setupRequired": bool(state["setupRequired"]),
        "databaseConnected": bool(state["databaseConnected"]),
        "setupTokenRequired": True,
        "status": state["status"],
    }


@app.post("/api/v1/setup/complete", status_code=201)
def complete_setup(payload: SetupCompleteRequest, request: Request):
    current = database_state()
    if not current["setupRequired"]:
        raise HTTPException(status_code=409, detail="System setup has already been completed")
    if len(settings.setup_token) < 32:
        raise HTTPException(status_code=503, detail="SETUP_TOKEN chưa được cấu hình an toàn trên máy chủ")
    if not hmac.compare_digest(payload.setup_token, settings.setup_token):
        raise HTTPException(status_code=403, detail="Setup token is invalid")

    database_url = build_database_url(payload.database)
    jwt_secret = settings.jwt_secret or secrets.token_hex(64)
    job_secret_key = settings.job_secret_key or Fernet.generate_key().decode()
    try:
        candidate = create_engine(database_url, pool_pre_ping=True)
        with candidate.connect() as connection:
            connection.execute(text("SELECT 1"))
        Base.metadata.create_all(candidate)
        candidate_factory = sessionmaker(bind=candidate, expire_on_commit=False)
        with candidate_factory() as db:
            ensure_builtin_roles(db)
            admin = db.execute(select(User).where(User.role == "admin", User.enabled.is_(True)).limit(1)).scalar_one_or_none()
            if admin is None:
                duplicate = db.execute(select(User).where(User.username == payload.admin.username)).scalar_one_or_none()
                if duplicate:
                    duplicate.role = "admin"
                    duplicate.enabled = True
                    duplicate.display_name = payload.admin.display_name
                    duplicate.password_hash = password_hasher.hash(payload.admin.password)
                    admin = duplicate
                else:
                    admin = User(username=payload.admin.username, display_name=payload.admin.display_name, password_hash=password_hasher.hash(payload.admin.password), role="admin")
                    db.add(admin)
            db.merge(SystemSetting(key="dashboard_url", value=payload.dashboard_url))
            audit(db, payload.admin.username, "system.setup.complete", "control-plane", request, detail={"dashboard_url": payload.dashboard_url})
            db.commit()
        save_bootstrap_config(database_url, jwt_secret, job_secret_key)
        settings.jwt_secret = jwt_secret
        settings.job_secret_key = job_secret_key
        with database_lock:
            global engine, SessionLocal, database_error
            previous = engine
            engine = candidate
            SessionLocal = candidate_factory
            settings.database_url = database_url
            database_error = ""
            if previous is not None and previous is not candidate:
                previous.dispose()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Không thể kết nối hoặc khởi tạo PostgreSQL. Hãy kiểm tra máy chủ, database, tài khoản và chế độ SSL.") from exc
    return {"status": "ready", "dashboardUrl": payload.dashboard_url, "adminUsername": payload.admin.username}


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(db_session)):
    scopes = auth_throttle_scopes(request, f"password:{payload.source}:{payload.username}")
    prune_auth_throttles(db)
    enforce_auth_throttle(db, scopes)
    user = authenticate_ldap(db, payload.username, payload.password) if payload.source == "domain" else db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    valid = payload.source == "domain" and user is not None
    if payload.source == "local" and user:
        try:
            valid = password_hasher.verify(user.password_hash, payload.password)
        except Exception:
            valid = False
    if not user or not valid or not user.enabled:
        record_auth_failure(db, scopes)
        audit(db, payload.username, f"auth.{payload.source}.login", "dashboard", request, "denied")
        db.commit()
        raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không đúng")
    clear_auth_throttle(db, scopes)
    audit(db, user.username, f"auth.{payload.source}.password", "dashboard", request)
    response = mfa_login_response(db, user)
    db.commit()
    return response


@app.post("/api/v1/auth/mfa/verify")
def verify_mfa_login(payload: MFAVerifyRequest, request: Request, db: Session = Depends(db_session)):
    try:
        claims = jwt.decode(payload.challenge_token, settings.jwt_secret, algorithms=["HS256"], issuer=settings.jwt_issuer)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Phiên MFA đã hết hạn") from exc
    if claims.get("purpose") != "mfa":
        raise HTTPException(status_code=401, detail="Phiên MFA không hợp lệ")
    user = db.get(User, claims.get("sub"))
    credential = db.get(MFACredential, claims.get("sub"))
    if not user or not credential or not user.enabled:
        raise HTTPException(status_code=401, detail="Tài khoản không hợp lệ")
    scopes = auth_throttle_scopes(request, f"mfa:{user.id}")
    prune_auth_throttles(db)
    enforce_auth_throttle(db, scopes)
    try:
        secret = job_fernet().decrypt(credential.secret_encrypted.encode()).decode()
    except InvalidToken as exc:
        raise HTTPException(status_code=503, detail="Không thể đọc cấu hình MFA") from exc
    totp = pyotp.TOTP(secret)
    counter = int(now().timestamp()) // totp.interval
    matched_counter = next((candidate for candidate in range(counter - 1, counter + 2) if candidate > credential.last_counter and hmac.compare_digest(totp.at(candidate * totp.interval), payload.code)), None)
    if matched_counter is None:
        record_auth_failure(db, scopes)
        audit(db, user.username, "auth.mfa", "dashboard", request, "denied")
        db.commit()
        raise HTTPException(status_code=401, detail="Mã MFA không đúng hoặc đã được sử dụng")
    clear_auth_throttle(db, scopes)
    credential.enrolled = True
    credential.last_counter = matched_counter
    audit(db, user.username, "auth.mfa", "dashboard", request)
    db.commit()
    return {"access_token": issue_jwt(user), "token_type": "bearer", "expires_in": settings.jwt_ttl_minutes * 60, "user": {"username": user.username, "displayName": user.display_name, "role": user.role}}


@app.get("/api/v1/me")
def me(user: User = Depends(current_user), db: Session = Depends(db_session)):
    return {"id": user.id, "username": user.username, "displayName": user.display_name, "role": user.role, "permissions": sorted(platform_role_permissions(db, user.role))}


def platform_user_json(user: User, db: Session | None = None) -> dict[str, Any]:
    group_ids = [] if db is None else list(db.execute(select(PlatformGroupMember.group_id).where(PlatformGroupMember.user_id == user.id)).scalars().all())
    return {"id": user.id, "username": user.username, "displayName": user.display_name, "role": user.role, "source": "ldap" if user.password_hash == "!LDAP" else "local", "enabled": user.enabled, "createdAt": aware(user.created_at).isoformat(), "groupIds": group_ids}


def platform_group_json(db: Session, group: PlatformGroup) -> dict[str, Any]:
    member_ids = list(db.execute(select(PlatformGroupMember.user_id).where(PlatformGroupMember.group_id == group.id).order_by(PlatformGroupMember.user_id)).scalars().all())
    return {"id": group.id, "name": group.name, "description": group.description, "memberIds": member_ids, "memberCount": len(member_ids), "createdAt": aware(group.created_at).isoformat()}


def validate_member_ids(db: Session, member_ids: list[str]) -> list[str]:
    normalized = list(dict.fromkeys(member_ids))
    if len(normalized) != len(member_ids) or any(not re.fullmatch(r"[0-9a-fA-F-]{36}", user_id) for user_id in normalized):
        raise HTTPException(status_code=422, detail="Danh sách thành viên không hợp lệ hoặc bị trùng")
    existing = set(db.execute(select(User.id).where(User.id.in_(normalized))).scalars().all()) if normalized else set()
    if existing != set(normalized):
        raise HTTPException(status_code=404, detail="Có thành viên không còn tồn tại")
    return normalized


def replace_platform_group_members(db: Session, group_id: str, member_ids: list[str]) -> None:
    normalized = validate_member_ids(db, member_ids)
    db.execute(delete(PlatformGroupMember).where(PlatformGroupMember.group_id == group_id))
    for user_id in normalized:
        db.add(PlatformGroupMember(group_id=group_id, user_id=user_id))


@app.get("/api/v1/users")
def list_users(_: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    return {"items": [platform_user_json(item, db) for item in users]}


@app.post("/api/v1/users", status_code=201)
def create_platform_user(payload: PlatformUserCreateRequest, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    if db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Tên đăng nhập đã tồn tại")
    validate_platform_role(db, payload.role)
    user = User(username=payload.username, display_name=payload.display_name, password_hash=password_hasher.hash(payload.password), role=payload.role)
    db.add(user)
    db.flush()
    audit(db, actor.username, "identity.local.create", user.id, request, detail={"username": user.username, "role": user.role})
    db.commit()
    return {**platform_user_json(user, db), "mfaEnrollmentRequired": True}


@app.patch("/api/v1/users/{user_id}")
def update_platform_user(user_id: str, payload: PlatformUserUpdateRequest, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Tài khoản không tồn tại")
    changes: dict[str, Any] = {}
    if payload.role is not None and payload.role != user.role:
        validate_platform_role(db, payload.role)
        if user.role == "admin" and user.enabled and db.execute(select(func.count()).select_from(User).where(User.role == "admin", User.enabled.is_(True), User.id != user.id)).scalar_one() == 0:
            raise HTTPException(status_code=409, detail="Không thể đổi role của quản trị viên cuối cùng")
        changes["role"] = {"from": user.role, "to": payload.role}
        user.role = payload.role
    if payload.enabled is not None and payload.enabled != user.enabled:
        if not payload.enabled and user.id == actor.id:
            raise HTTPException(status_code=409, detail="Không thể tự khóa tài khoản đang đăng nhập")
        if not payload.enabled and user.role == "admin" and db.execute(select(func.count()).select_from(User).where(User.role == "admin", User.enabled.is_(True), User.id != user.id)).scalar_one() == 0:
            raise HTTPException(status_code=409, detail="Không thể khóa quản trị viên cuối cùng")
        changes["enabled"] = payload.enabled
        user.enabled = payload.enabled
    if payload.display_name is not None and payload.display_name.strip() != user.display_name:
        user.display_name = payload.display_name.strip()
        changes["display_name"] = True
    if payload.password:
        if user.password_hash == "!LDAP":
            raise HTTPException(status_code=422, detail="Mật khẩu LDAP phải đổi tại Active Directory; website chỉ cho đổi role của user LDAP")
        user.password_hash = password_hasher.hash(payload.password)
        changes["password"] = "changed"
    if not changes:
        raise HTTPException(status_code=422, detail="Không có thay đổi hợp lệ")
    audit(db, actor.username, "identity.user.update", user.id, request, detail={"username": user.username, "source": "ldap" if user.password_hash == "!LDAP" else "local", "changes": changes})
    db.commit()
    return platform_user_json(user, db)


@app.delete("/api/v1/users")
def delete_platform_users(payload: PlatformUsersDeleteRequest, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    user_ids = list(dict.fromkeys(payload.user_ids))
    if len(user_ids) != len(payload.user_ids) or any(not re.fullmatch(r"[0-9a-fA-F-]{36}", user_id) for user_id in user_ids):
        raise HTTPException(status_code=422, detail="Danh sách tài khoản không hợp lệ hoặc bị trùng")
    if actor.id in user_ids:
        raise HTTPException(status_code=409, detail="Không thể tự xóa tài khoản đang đăng nhập")
    users = db.execute(select(User).where(User.id.in_(user_ids))).scalars().all()
    if len(users) != len(user_ids):
        raise HTTPException(status_code=404, detail="Có tài khoản không còn tồn tại")
    deleting_admins = sum(1 for user in users if user.role == "admin" and user.enabled)
    remaining_admins = db.execute(select(func.count()).select_from(User).where(User.role == "admin", User.enabled.is_(True), User.id.not_in(user_ids))).scalar_one()
    if deleting_admins and remaining_admins == 0:
        raise HTTPException(status_code=409, detail="Không thể xóa quản trị viên cuối cùng")
    referenced = set(db.execute(select(RecordingDeletionRequest.requested_by).where(RecordingDeletionRequest.requested_by.in_(user_ids))).scalars().all())
    referenced.update(item for item in db.execute(select(RecordingDeletionRequest.approved_by).where(RecordingDeletionRequest.approved_by.in_(user_ids))).scalars().all() if item)
    if referenced:
        raise HTTPException(status_code=409, detail="Có tài khoản đã phát sinh yêu cầu recording; hãy khóa tài khoản thay vì xóa để giữ toàn vẹn audit")
    db.execute(delete(MFACredential).where(MFACredential.user_id.in_(user_ids)))
    db.execute(delete(PlatformGroupMember).where(PlatformGroupMember.user_id.in_(user_ids)))
    db.execute(delete(ServerUserShare).where(ServerUserShare.user_id.in_(user_ids)))
    db.execute(delete(User).where(User.id.in_(user_ids)))
    audit(db, actor.username, "identity.user.delete", "platform-users", request, detail={"users": [{"id": user.id, "username": user.username, "source": "ldap" if user.password_hash == "!LDAP" else "local"} for user in users]})
    db.commit()
    return {"deleted": len(users)}


@app.get("/api/v1/platform-groups")
def list_platform_groups(_: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    groups = db.execute(select(PlatformGroup).order_by(PlatformGroup.name)).scalars().all()
    return {"items": [platform_group_json(db, group) for group in groups]}


@app.post("/api/v1/platform-groups", status_code=201)
def create_platform_group(payload: PlatformGroupRequest, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    name = payload.name.strip()
    if db.execute(select(PlatformGroup).where(func.lower(PlatformGroup.name) == name.lower())).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Tên group đã tồn tại")
    group = PlatformGroup(name=name, description=payload.description.strip(), created_by=actor.id)
    db.add(group)
    db.flush()
    replace_platform_group_members(db, group.id, payload.member_ids)
    audit(db, actor.username, "identity.group.create", group.id, request, detail={"name": group.name, "member_count": len(payload.member_ids)})
    db.commit()
    return platform_group_json(db, group)


@app.put("/api/v1/platform-groups/{group_id}")
def update_platform_group(group_id: str, payload: PlatformGroupRequest, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    group = db.get(PlatformGroup, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group không tồn tại")
    name = payload.name.strip()
    duplicate = db.execute(select(PlatformGroup).where(func.lower(PlatformGroup.name) == name.lower(), PlatformGroup.id != group.id)).scalar_one_or_none()
    if duplicate:
        raise HTTPException(status_code=409, detail="Tên group đã tồn tại")
    group.name = name
    group.description = payload.description.strip()
    replace_platform_group_members(db, group.id, payload.member_ids)
    audit(db, actor.username, "identity.group.update", group.id, request, detail={"name": group.name, "member_count": len(payload.member_ids)})
    db.commit()
    return platform_group_json(db, group)


@app.put("/api/v1/users/{user_id}/groups")
def update_platform_user_groups(user_id: str, payload: PlatformGroupMembersRequest, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Tài khoản không tồn tại")
    group_ids = list(dict.fromkeys(payload.member_ids))
    if len(group_ids) != len(payload.member_ids):
        raise HTTPException(status_code=422, detail="Danh sách group bị trùng")
    groups = db.execute(select(PlatformGroup.id).where(PlatformGroup.id.in_(group_ids))).scalars().all() if group_ids else []
    if set(groups) != set(group_ids):
        raise HTTPException(status_code=404, detail="Có group không còn tồn tại")
    db.execute(delete(PlatformGroupMember).where(PlatformGroupMember.user_id == user.id))
    for group_id in group_ids:
        db.add(PlatformGroupMember(group_id=group_id, user_id=user.id))
    audit(db, actor.username, "identity.user.groups", user.id, request, detail={"group_ids": group_ids})
    db.commit()
    return platform_user_json(user, db)


@app.delete("/api/v1/platform-groups/{group_id}")
def delete_platform_group(group_id: str, request: Request, actor: User = Depends(require_permission("users.manage")), db: Session = Depends(db_session)):
    group = db.get(PlatformGroup, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group không tồn tại")
    db.execute(delete(ServerGroupShare).where(ServerGroupShare.group_id == group.id))
    db.execute(delete(PlatformGroupMember).where(PlatformGroupMember.group_id == group.id))
    db.delete(group)
    audit(db, actor.username, "identity.group.delete", group.id, request, detail={"name": group.name})
    db.commit()
    return {"deleted": group_id}


@app.get("/api/v1/roles")
def list_platform_roles(_: User = Depends(current_user), db: Session = Depends(db_session)):
    ensure_builtin_roles(db)
    db.commit()
    roles = db.execute(select(PlatformRole).order_by(PlatformRole.system.desc(), PlatformRole.name)).scalars().all()
    return {"items": [platform_role_json(role) for role in roles], "permissionCatalog": [{"id": permission, **detail} for permission, detail in PERMISSION_CATALOG.items()]}


@app.post("/api/v1/roles", status_code=201)
def create_platform_role(payload: PlatformRoleRequest, request: Request, actor: User = Depends(require_permission("roles.manage")), db: Session = Depends(db_session)):
    if db.get(PlatformRole, payload.name):
        raise HTTPException(status_code=409, detail="Tên role đã tồn tại")
    role = PlatformRole(name=payload.name, display_name=payload.display_name.strip(), description=payload.description.strip(), permissions=normalize_permissions(payload.permissions), system=False)
    db.add(role)
    db.flush()
    audit(db, actor.username, "identity.role.create", role.name, request, detail={"permissions": role.permissions})
    db.commit()
    return platform_role_json(role)


@app.put("/api/v1/roles/{role_name}")
def update_platform_role(role_name: str, payload: PlatformRoleUpdateRequest, request: Request, actor: User = Depends(require_permission("roles.manage")), db: Session = Depends(db_session)):
    role = db.get(PlatformRole, role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role không tồn tại")
    if role.system:
        raise HTTPException(status_code=409, detail="Role có sẵn được khóa để luôn giữ baseline an toàn; hãy tạo role tùy chỉnh")
    role.display_name = payload.display_name.strip()
    role.description = payload.description.strip()
    role.permissions = normalize_permissions(payload.permissions)
    audit(db, actor.username, "identity.role.update", role.name, request, detail={"permissions": role.permissions})
    db.commit()
    return platform_role_json(role)


@app.delete("/api/v1/roles/{role_name}")
def delete_platform_role(role_name: str, request: Request, actor: User = Depends(require_permission("roles.manage")), db: Session = Depends(db_session)):
    role = db.get(PlatformRole, role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role không tồn tại")
    if role.system:
        raise HTTPException(status_code=409, detail="Không thể xóa role có sẵn")
    if db.execute(select(User).where(User.role == role.name).limit(1)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Role đang được gán cho người dùng; hãy đổi role của họ trước")
    if read_ldap_config(db).get("default_role") == role.name:
        raise HTTPException(status_code=409, detail="Role đang là mặc định LDAP; hãy đổi cấu hình LDAP trước")
    db.delete(role)
    audit(db, actor.username, "identity.role.delete", role.name, request)
    db.commit()
    return {"deleted": role_name}


@app.get("/api/v1/settings/ldap")
def get_ldap_config(_: User = Depends(require_permission("ldap.manage")), db: Session = Depends(db_session)):
    config = read_ldap_config(db)
    config.pop("bind_password", None)
    return config


@app.get("/api/v1/settings/ldap/groups")
def scan_ldap_groups(query: str = "", _: User = Depends(require_permission("ldap.manage")), db: Session = Depends(db_session)):
    if len(query) > 80 or any(ord(character) < 32 for character in query):
        raise HTTPException(status_code=422, detail="Từ khóa tìm group không hợp lệ")
    config = read_ldap_config(db, include_secret=True)
    if not config.get("host") or not config.get("base_dn"):
        raise HTTPException(status_code=409, detail="Hãy cấu hình LDAP Host và Base DN trước khi quét group")
    try:
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=config.get("ca_certificate") or None) if config.get("use_ssl", True) else None
        ldap_server = LDAPServer(config["host"], port=int(config.get("port", 636)), use_ssl=bool(config.get("use_ssl", True)), tls=tls, get_info=ALL, connect_timeout=8)
        with Connection(ldap_server, user=config.get("bind_dn") or None, password=config.get("bind_password") or None, auto_bind=True, receive_timeout=15) as service:
            term = escape_filter_chars(query.strip())
            group_filter = f"(&(objectClass=group)(|(cn=*{term}*)(name=*{term}*)))" if term else "(objectClass=group)"
            service.search(config["base_dn"], group_filter, search_scope=SUBTREE, attributes=["cn", "name"], size_limit=200)
            items = []
            for entry in service.entries:
                name_value = getattr(entry, "cn", None) or getattr(entry, "name", None)
                items.append({"dn": entry.entry_dn, "name": str(name_value.value) if name_value and name_value.value else entry.entry_dn})
            items.sort(key=lambda item: item["name"].casefold())
            return {"items": items}
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Không thể quét group LDAP. Kiểm tra kết nối và quyền đọc directory của Bind DN.") from exc


@app.put("/api/v1/settings/ldap")
def update_ldap_config(payload: LDAPConfigRequest, request: Request, user: User = Depends(require_permission("ldap.manage")), db: Session = Depends(db_session)):
    if payload.enabled and (not payload.host or not payload.base_dn):
        raise HTTPException(status_code=400, detail="LDAP host và Base DN là bắt buộc")
    current = read_ldap_config(db, include_secret=True)
    bind_password = payload.bind_password or current.get("bind_password", "")
    validate_platform_role(db, payload.default_role, ldap_default=True)
    if payload.enabled:
        try:
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=payload.ca_certificate or None) if payload.use_ssl else None
            ldap_server = LDAPServer(payload.host, port=payload.port, use_ssl=payload.use_ssl, tls=tls, get_info=ALL, connect_timeout=8)
            with Connection(ldap_server, user=payload.bind_dn or None, password=bind_password or None, auto_bind=True, receive_timeout=10) as service:
                for group_dn in payload.allowed_group_dns:
                    if not service.search(group_dn, "(objectClass=group)", search_scope=BASE, attributes=["distinguishedName"], size_limit=1) or len(service.entries) != 1:
                        raise ValueError(f"LDAP group không tồn tại hoặc Bind DN không đọc được: {group_dn}")
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Không thể bind LDAP. Kiểm tra host, certificate LDAPS, Bind DN và mật khẩu.") from exc
    serialized = payload.model_dump(exclude={"bind_password"})
    if bind_password:
        serialized["bind_password_encrypted"] = job_fernet().encrypt(bind_password.encode()).decode()
    db.merge(SystemSetting(key="ldap_config", value=json.dumps(serialized, separators=(",", ":"))))
    audit(db, user.username, "settings.ldap.update", payload.host, request, detail={"enabled": payload.enabled, "use_ssl": payload.use_ssl, "allowed_group_count": len(payload.allowed_group_dns)})
    db.commit()
    return {**serialized, "password_configured": bool(bind_password)}


def retired_server_ids(db: Session) -> set[str]:
    return set(db.execute(select(ServerRetirement.server_id)).scalars().all())


def visible_server_ids(db: Session, user: User) -> set[str]:
    active_ids = set(db.execute(select(Server.id)).scalars().all()) - retired_server_ids(db)
    if user.role == "admin":
        return active_ids
    direct = set(db.execute(select(ServerUserShare.server_id).where(ServerUserShare.user_id == user.id)).scalars().all())
    group_ids = set(db.execute(select(PlatformGroupMember.group_id).where(PlatformGroupMember.user_id == user.id)).scalars().all())
    grouped = set(db.execute(select(ServerGroupShare.server_id).where(ServerGroupShare.group_id.in_(group_ids))).scalars().all()) if group_ids else set()
    return active_ids & (direct | grouped)


def visible_server(db: Session, user: User, server_id: str) -> Server:
    server = db.get(Server, server_id)
    if not server or server_id not in visible_server_ids(db, user):
        raise HTTPException(status_code=404, detail="Server not found")
    return server


def require_server_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Chỉ Administrator được xóa hoặc chia sẻ máy chủ")


def server_shares_json(db: Session, server_id: str) -> dict[str, Any]:
    user_ids = list(db.execute(select(ServerUserShare.user_id).where(ServerUserShare.server_id == server_id).order_by(ServerUserShare.user_id)).scalars().all())
    group_ids = list(db.execute(select(ServerGroupShare.group_id).where(ServerGroupShare.server_id == server_id).order_by(ServerGroupShare.group_id)).scalars().all())
    return {"userIds": user_ids, "groupIds": group_ids, "count": len(user_ids) + len(group_ids)}


@app.get("/api/v1/servers")
def list_servers(os_family: Literal["windows", "linux"] | None = None, user: User = Depends(require_permission("servers.view")), db: Session = Depends(db_session)):
    query = select(Server).order_by(Server.os_family, Server.name)
    if os_family:
        query = query.where(Server.os_family == os_family)
    allowed = visible_server_ids(db, user)
    query = query.where(Server.id.in_(allowed))
    items = []
    for item in db.execute(query).scalars().all():
        serialized = server_json(item)
        if user.role == "admin":
            serialized["shares"] = server_shares_json(db, item.id)
        items.append(serialized)
    return {"items": items}


@app.get("/api/v1/servers/{server_id}")
def get_server(server_id: str, user: User = Depends(require_permission("servers.view")), db: Session = Depends(db_session)):
    server = visible_server(db, user, server_id)
    return {**server_json(server), "inventory": server.inventory}


@app.get("/api/v1/servers/{server_id}/shares")
def get_server_shares(server_id: str, user: User = Depends(require_permission("servers.manage")), db: Session = Depends(db_session)):
    require_server_admin(user)
    server = visible_server(db, user, server_id)
    return {"serverId": server.id, **server_shares_json(db, server.id)}


@app.put("/api/v1/servers/{server_id}/shares")
def update_server_shares(server_id: str, payload: ServerSharesRequest, request: Request, user: User = Depends(require_permission("servers.manage")), db: Session = Depends(db_session)):
    require_server_admin(user)
    server = visible_server(db, user, server_id)
    user_ids = list(dict.fromkeys(payload.user_ids))
    group_ids = list(dict.fromkeys(payload.group_ids))
    if len(user_ids) != len(payload.user_ids) or len(group_ids) != len(payload.group_ids):
        raise HTTPException(status_code=422, detail="Danh sách share bị trùng")
    if set(db.execute(select(User.id).where(User.id.in_(user_ids))).scalars().all()) != set(user_ids):
        raise HTTPException(status_code=404, detail="Có user share không còn tồn tại")
    if set(db.execute(select(PlatformGroup.id).where(PlatformGroup.id.in_(group_ids))).scalars().all()) != set(group_ids):
        raise HTTPException(status_code=404, detail="Có group share không còn tồn tại")
    db.execute(delete(ServerUserShare).where(ServerUserShare.server_id == server.id))
    db.execute(delete(ServerGroupShare).where(ServerGroupShare.server_id == server.id))
    for user_id in user_ids:
        db.add(ServerUserShare(server_id=server.id, user_id=user_id, granted_by=user.id))
    for group_id in group_ids:
        db.add(ServerGroupShare(server_id=server.id, group_id=group_id, granted_by=user.id))
    audit(db, user.username, "server.share.update", server.id, request, detail={"user_ids": user_ids, "group_ids": group_ids})
    db.commit()
    return {"serverId": server.id, **server_shares_json(db, server.id)}


@app.delete("/api/v1/servers/{server_id}")
def delete_server(server_id: str, payload: ServerDeleteRequest, request: Request, user: User = Depends(require_permission("servers.manage")), db: Session = Depends(db_session)):
    require_server_admin(user)
    server = visible_server(db, user, server_id)
    active_session = db.execute(select(RemoteSession).where(RemoteSession.server_id == server.id, RemoteSession.status.in_(["waiting", "launched", "active"])).limit(1)).scalar_one_or_none()
    active_job = db.execute(select(Job).where(Job.server_id == server.id, Job.status == "dispatched").limit(1)).scalar_one_or_none()
    if active_session or active_job:
        raise HTTPException(status_code=409, detail="Máy chủ đang có phiên hoặc tác vụ hoạt động; hãy kết thúc trước khi xóa")
    db.execute(update(Job).where(Job.server_id == server.id, Job.status == "queued").values(status="failed", finished_at=now(), exit_code=410, output="Server retired by Administrator"))
    db.execute(delete(ServerUserShare).where(ServerUserShare.server_id == server.id))
    db.execute(delete(ServerGroupShare).where(ServerGroupShare.server_id == server.id))
    db.add(ServerRetirement(server_id=server.id, retired_by=user.id, reason=payload.reason.strip()))
    server.status = "retired"
    audit(db, user.username, "server.delete", server.id, request, detail={"name": server.name, "reason": payload.reason.strip(), "retained_for_audit": True})
    db.commit()
    return {"deleted": server.id, "retainedForAudit": True}


def log_sources_setting_key(server_id: str) -> str:
    return f"log_sources:{server_id}"


def configured_log_sources(db: Session, server: Server) -> list[str]:
    setting = db.get(SystemSetting, log_sources_setting_key(server.id))
    if setting:
        try:
            parsed = json.loads(setting.value)
            if isinstance(parsed, list) and parsed:
                return [str(item) for item in parsed[:20]]
        except (TypeError, ValueError):
            pass
    return ["System"] if server.os_family == "windows" else ["journal"]


INITIAL_SERVER_SCAN_ACTIONS = (
    "inventory.collect",
    "storage.list",
    "service.list",
    "user.list",
    "group.list",
    "firewall.list",
    "process.list",
    "network.list",
    "logs.sources",
    "logs.read",
    "patch.scan",
)


def queue_initial_server_scan(db: Session, server: Server, actor: str) -> list[str]:
    job_ids: list[str] = []
    for action in INITIAL_SERVER_SCAN_ACTIONS:
        parameters = {"limit": 500, "sources": configured_log_sources(db, server)} if action == "logs.read" else {}
        job = Job(
            server_id=server.id,
            action=action,
            parameters=parameters,
            reason="Tự động quét dữ liệu ban đầu sau khi cài Agent",
            status="queued",
            risk=SAFE_ACTIONS[action]["risk"],
            created_by=actor,
        )
        db.add(job)
        db.flush()
        job_ids.append(job.id)
    audit(db, actor, "server.initial_scan.queued", server.id, detail={"actions": list(INITIAL_SERVER_SCAN_ACTIONS), "job_ids": job_ids})
    return job_ids


def validate_log_sources(server: Server, sources: list[str]) -> list[str]:
    normalized = list(dict.fromkeys(source.strip() for source in sources))
    if not 1 <= len(normalized) <= 20 or any(not source for source in normalized):
        raise HTTPException(status_code=422, detail="Select between 1 and 20 log sources")
    if server.os_family == "windows":
        if any(not re.fullmatch(r"[A-Za-z0-9_. /-]{1,180}", source) for source in normalized):
            raise HTTPException(status_code=422, detail="Invalid Windows Event Log source")
    else:
        for source in normalized:
            if source == "journal":
                continue
            path = PurePosixPath(source)
            if not source.startswith("/var/log/") or ".." in path.parts or len(source) > 300:
                raise HTTPException(status_code=422, detail="Linux log files must be below /var/log")
    return normalized


@app.get("/api/v1/servers/{server_id}/log-sources")
def get_server_log_sources(server_id: str, user: User = Depends(require_permission("logs.view")), db: Session = Depends(db_session)):
    server = visible_server(db, user, server_id)
    return {"sources": configured_log_sources(db, server)}


@app.put("/api/v1/servers/{server_id}/log-sources")
def update_server_log_sources(payload: LogSourcesUpdateRequest, server_id: str, request: Request, user: User = Depends(require_permission("logs.view")), db: Session = Depends(db_session)):
    server = visible_server(db, user, server_id)
    sources = validate_log_sources(server, payload.sources)
    db.merge(SystemSetting(key=log_sources_setting_key(server.id), value=json.dumps(sources, ensure_ascii=False, separators=(",", ":"))))
    audit(db, user.username, "logs.sources.update", server.id, request, detail={"sources": sources})
    db.commit()
    return {"sources": sources}


def job_json(job: Job, *, include_output: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": job.id,
        "serverId": job.server_id,
        "action": job.action,
        "status": job.status,
        "risk": job.risk,
        "reason": job.reason,
        "createdAt": aware(job.created_at).isoformat(),
        "startedAt": aware(job.started_at).isoformat() if job.started_at else None,
        "finishedAt": aware(job.finished_at).isoformat() if job.finished_at else None,
        "exitCode": job.exit_code,
    }
    if include_output:
        payload["output"] = job.output
    return payload


def can_view_job_output(user: User, action: str, db: Session) -> bool:
    permission = "files.view" if action == "file.deliver" else ACTION_PERMISSIONS.get(action)
    return bool(permission and permission in platform_role_permissions(db, user.role))


@app.get("/api/v1/servers/{server_id}/jobs")
def list_server_jobs(server_id: str, user: User = Depends(require_permission("servers.view")), db: Session = Depends(db_session)):
    visible_server(db, user, server_id)
    jobs = db.execute(select(Job).where(Job.server_id == server_id).order_by(Job.created_at.desc()).limit(100)).scalars().all()
    return {
        "items": [
            job_json(job, include_output=can_view_job_output(user, job.action, db))
            for job in jobs
        ]
    }


def file_transfer_json(transfer: FileTransfer) -> dict[str, Any]:
    return {
        "id": transfer.id,
        "serverId": transfer.server_id,
        "jobId": transfer.job_id,
        "filename": transfer.original_name,
        "contentType": transfer.content_type,
        "sizeBytes": transfer.size_bytes,
        "sha256": transfer.sha256,
        "status": transfer.status,
        "scanResult": transfer.scan_result,
        "reason": transfer.reason,
        "createdAt": aware(transfer.created_at).isoformat(),
        "deliveredAt": aware(transfer.delivered_at).isoformat() if transfer.delivered_at else None,
    }


@app.get("/api/v1/servers/{server_id}/files")
def list_server_files(server_id: str, user: User = Depends(require_permission("files.view")), db: Session = Depends(db_session)):
    visible_server(db, user, server_id)
    if expire_file_payloads(db):
        db.commit()
    transfers = db.execute(select(FileTransfer).where(FileTransfer.server_id == server_id).order_by(FileTransfer.created_at.desc()).limit(100)).scalars().all()
    return {"items": [file_transfer_json(item) for item in transfers]}


@app.post("/api/v1/servers/{server_id}/files", status_code=201)
async def upload_server_file(
    server_id: str,
    request: Request,
    file: UploadFile = File(...),
    reason: str = Form(..., min_length=5, max_length=2000),
    user: User = Depends(require_permission("files.manage")),
    db: Session = Depends(db_session),
):
    server = visible_server(db, user, server_id)
    try:
        filename = normalize_upload_name(file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    content = bytearray()
    digest = hashlib.sha256()
    while chunk := await file.read(64 * 1024):
        if len(content) + len(chunk) > settings.file_max_bytes:
            audit(db, user.username, "file.upload.blocked", server_id, request, "blocked", {"filename": filename, "reason": "size-limit"})
            db.commit()
            await file.close()
            raise HTTPException(status_code=413, detail=f"File exceeds the {settings.file_max_bytes // (1024 * 1024)} MiB limit")
        content.extend(chunk)
        digest.update(chunk)
    await file.close()
    if not content:
        raise HTTPException(status_code=400, detail="Empty files are not accepted")

    transfer_id = str(uuid.uuid4())
    sha256 = digest.hexdigest()
    content_type = (file.content_type or "application/octet-stream")[:255]
    try:
        scan_result = await asyncio.to_thread(
            scan_with_clamav,
            bytes(content),
            settings.clamav_host,
            settings.clamav_port,
            settings.clamav_timeout_seconds,
        )
    except MalwareDetected as exc:
        transfer = FileTransfer(id=transfer_id, server_id=server.id, original_name=filename, content_type=content_type, size_bytes=len(content), sha256=sha256, status="blocked", scan_result=str(exc)[:255], reason=reason, created_by=user.id)
        db.add(transfer)
        audit(db, user.username, "file.upload.blocked", transfer.id, request, "blocked", {"server": server.name, "filename": filename, "sha256": sha256, "scanner": "clamav", "signature": exc.signature})
        db.commit()
        raise HTTPException(status_code=422, detail="Malware scanner blocked this file") from exc
    except ScannerUnavailable as exc:
        transfer = FileTransfer(id=transfer_id, server_id=server.id, original_name=filename, content_type=content_type, size_bytes=len(content), sha256=sha256, status="scan_failed", scan_result=str(exc)[:255], reason=reason, created_by=user.id)
        db.add(transfer)
        audit(db, user.username, "file.upload.scan_failed", transfer.id, request, "failed", {"server": server.name, "filename": filename, "sha256": sha256})
        db.commit()
        raise HTTPException(status_code=503, detail="Malware scanner is unavailable; file was not stored") from exc

    encrypted, nonce = encrypt_file(bytes(content), transfer_id, server.id, sha256, settings.job_secret_key)
    transfer = FileTransfer(id=transfer_id, server_id=server.id, original_name=filename, content_type=content_type, size_bytes=len(content), sha256=sha256, status="queued", scan_result=scan_result[:255], reason=reason, created_by=user.id, content_encrypted=encrypted, nonce=nonce)
    job = Job(server_id=server.id, action="file.deliver", parameters={"transfer_id": transfer.id, "filename": filename, "sha256": sha256, "size_bytes": len(content)}, reason=reason, status="queued", risk="critical", created_by=user.id)
    db.add_all([transfer, job])
    db.flush()
    transfer.job_id = job.id
    audit(db, user.username, "file.upload.clean", transfer.id, request, detail={"server": server.name, "filename": filename, "size": len(content), "sha256": sha256, "scanner": "clamav", "delivery": "direct"})
    db.commit()
    return {**file_transfer_json(transfer), "note": "The clean file is queued for the agent"}


@app.post("/api/v1/enrollment-tokens", status_code=201)
def create_enrollment_token(payload: EnrollmentTokenRequest, request: Request, user: User = Depends(require_permission("agents.manage")), db: Session = Depends(db_session)):
    raw = "tvo_" + secrets.token_urlsafe(32)
    record = EnrollmentToken(token_hash=token_digest(raw), label=payload.label, expected_os_family=payload.expected_os_family, max_uses=payload.max_uses, expires_at=now() + timedelta(hours=payload.expires_hours), created_by=user.id)
    db.add(record)
    audit(db, user.username, "enrollment.token.create", record.id, request, detail={"label": payload.label, "expected_os_family": payload.expected_os_family, "max_uses": payload.max_uses})
    db.commit()
    return {"id": record.id, "token": raw, "expiresAt": record.expires_at.isoformat(), "note": "Token is shown once"}


def canonical_dashboard_url(db: Session) -> str:
    canonical = db.get(SystemSetting, "dashboard_url")
    if not canonical:
        raise HTTPException(status_code=409, detail="Complete setup with the real HTTPS dashboard URL before generating an agent")
    normalized = canonical.value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise HTTPException(status_code=409, detail="The configured dashboard URL must be an origin-only HTTPS URL")
    return normalized


def agent_endpoint_for_dashboard(dashboard_url: str) -> str:
    hostname = urlsplit(dashboard_url).hostname
    if not hostname:
        raise HTTPException(status_code=409, detail="Dashboard hostname is unavailable")
    formatted_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"https://{formatted_host}:9443/api/v1/agent"


def issue_agent_identity(
    *,
    agent_id: str,
    csr_pem: str,
    inventory: Inventory,
    request: Request,
    db: Session,
    actor: str,
    initial_scan_created_by: str,
    allow_rotation: bool,
) -> dict[str, Any]:
    try:
        uuid.UUID(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="agent_id must be a UUID") from exc
    family, verification = classify_os(inventory)
    existing = db.get(Server, agent_id)
    if existing and not allow_rotation:
        raise HTTPException(status_code=409, detail="Bootstrap packages cannot replace an existing agent identity")
    cert_pem, fingerprint, cert_expires = sign_agent_csr(csr_pem, agent_id)
    server_ca_certificate, _ = read_agent_server_ca()
    try:
        agent_ca_certificate = Path(settings.agent_ca_cert).read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Control-plane PKI is unavailable; restart Caddy/API and retry enrollment") from exc
    replacing_certificate = bool(existing and existing.cert_fingerprint)
    remote_protocol = "rdp" if family == "windows" else "ssh"
    server = existing or Server(id=agent_id, name=inventory.hostname, os_family=family, os_name=inventory.os_name)
    server.name = inventory.hostname
    server.os_family = family
    server.os_name = inventory.os_name
    server.os_version = inventory.os_version
    server.distribution_id = inventory.distribution_id
    server.architecture = inventory.architecture
    server.address = next((address for address in inventory.addresses if not address.startswith("127.") and address != "::1"), "")
    server.agent_version = inventory.agent_version
    server.cert_fingerprint = fingerprint
    server.cert_expires_at = cert_expires
    server.last_seen = now()
    server.status = "online"
    server.inventory = inventory.model_dump()
    server.ssh_host_key = inventory.ssh_host_key
    server.remote_protocol = remote_protocol
    server.verified_os = verification == "verified"
    db.add(server)
    db.flush()
    if existing is None:
        # Job.created_by is a 36-character user id. Audit actors intentionally
        # include a namespace (for example ``bootstrap:<package UUID>``) and
        # must never be stored in that narrower column. PostgreSQL enforces the
        # limit even though SQLite-based unit tests do not.
        queue_initial_server_scan(db, server, initial_scan_created_by)
    action = "agent.certificate.rotate" if replacing_certificate else "agent.enroll"
    audit(db, actor, action, agent_id, request, detail={"os_family": family, "distribution": inventory.distribution_id, "verified": server.verified_os})
    try:
        dashboard_url = canonical_dashboard_url(db)
    except HTTPException:
        request_host = request.url.hostname
        if not request_host:
            raise
        dashboard_url = f"https://{request_host}"
    return {
        "agent_id": agent_id,
        "certificate": cert_pem,
        "ca_certificate": agent_ca_certificate,
        "server_ca_certificate": server_ca_certificate,
        "expires_at": cert_expires.isoformat(),
        "os_family": family,
        "category": "Windows" if family == "windows" else "Linux",
        "agent_endpoint": agent_endpoint_for_dashboard(dashboard_url),
    }


@app.get("/api/v1/agent-packages/status")
def agent_package_status(_: User = Depends(require_permission("agents.manage")), db: Session = Depends(db_session)):
    dashboard_url = canonical_dashboard_url(db)
    try:
        validate_linux_agent(Path(settings.agent_assets_root) / LINUX_AGENT_PATH)
        linux_available = True
    except (FileNotFoundError, ValueError):
        linux_available = False
    return {
        "dashboardUrl": dashboard_url,
        "agentVersion": RELEASE_VERSION,
        "linuxAvailable": linux_available,
        "windowsMsiAvailable": Path(settings.windows_agent_msi).is_file(),
        "agentTlsCaAvailable": agent_server_ca_available(),
        "claimTtlMinutes": 30,
        "webTlsTrust": settings.web_tls_trust,
    }


@app.put("/api/v1/settings/dashboard-url")
def update_dashboard_url(payload: DashboardUrlUpdateRequest, request: Request, user: User = Depends(require_permission("agents.manage")), db: Session = Depends(db_session)):
    request_host = request.url.hostname
    requested_host = urlsplit(payload.dashboard_url).hostname
    if request_host and request_host not in {"testserver", "localhost", "127.0.0.1"} and requested_host != request_host:
        raise HTTPException(status_code=400, detail="Open the dashboard through the requested HTTPS domain before saving it")
    current = db.get(SystemSetting, "dashboard_url")
    previous = current.value if current else ""
    has_agents = db.execute(select(Server.id).limit(1)).scalar_one_or_none() is not None
    if previous and previous != payload.dashboard_url and has_agents and not payload.confirm_existing_agents:
        raise HTTPException(status_code=409, detail="Existing agents keep their old endpoint; confirm the domain change after planning their migration")
    db.merge(SystemSetting(key="dashboard_url", value=payload.dashboard_url))
    audit(db, user.username, "system.dashboard_url.update", "control-plane", request, detail={"previous": previous, "dashboard_url": payload.dashboard_url, "existing_agents": has_agents})
    db.commit()
    return {"dashboardUrl": payload.dashboard_url, "existingAgentsNeedMigration": bool(has_agents and previous != payload.dashboard_url)}


@app.post("/api/v1/agent-packages")
def create_agent_package(payload: AgentPackageRequest, request: Request, user: User = Depends(require_permission("agents.manage")), db: Session = Depends(db_session)):
    dashboard_url = canonical_dashboard_url(db)
    ca_certificate, ca_fingerprint = read_agent_server_ca()
    bootstrap_ca_certificate = ca_certificate if settings.web_tls_trust == "internal-ca" else ""
    bootstrap_tls_pin = ca_fingerprint if settings.web_tls_trust == "internal-ca" else "system"
    package_id = str(uuid.uuid4())
    package_secret = secrets.token_urlsafe(32)
    safe_label = safe_package_label(payload.label)
    expires_at = now() + timedelta(minutes=payload.expires_minutes)
    try:
        if payload.os_family == "linux":
            content = linux_run_bundle(
                Path(settings.agent_assets_root),
                dashboard_url=dashboard_url,
                package_id=package_id,
                package_secret=package_secret,
                ca_certificate=bootstrap_ca_certificate,
                ca_fingerprint=bootstrap_tls_pin,
            )
            filename = f"TramAgent-Linux-{safe_label}.run"
            media_type = "application/octet-stream"
        else:
            content = validate_windows_msi(Path(settings.windows_agent_msi))
            filename = windows_msi_filename(dashboard_url, package_id, package_secret, bootstrap_tls_pin)
            media_type = "application/x-msi"
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    record = AgentBootstrapPackage(
        id=package_id,
        secret_hash=token_digest(package_secret),
        label=payload.label,
        expected_os_family=payload.os_family,
        created_by=user.id,
        expires_at=expires_at,
    )
    db.add(record)
    audit(db, user.username, "agent.package.create", record.id, request, detail={"label": payload.label, "os_family": payload.os_family, "expires_at": expires_at.isoformat(), "dashboard_url": dashboard_url, "web_tls_trust": settings.web_tls_trust})
    db.commit()
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "X-Tram-Package-Expires": expires_at.isoformat(),
        },
    )


@app.post("/api/v1/agent-bootstrap/claim", status_code=201)
def claim_agent_package(payload: AgentBootstrapClaimRequest, request: Request, db: Session = Depends(db_session)):
    try:
        uuid.UUID(payload.package_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Bootstrap claim is invalid or expired") from exc
    record = db.execute(select(AgentBootstrapPackage).where(AgentBootstrapPackage.id == payload.package_id).with_for_update()).scalar_one_or_none()
    supplied_hash = token_digest(payload.package_secret)
    if not record or not hmac.compare_digest(record.secret_hash, supplied_hash) or record.used_at is not None or aware(record.expires_at) < now():
        raise HTTPException(status_code=401, detail="Bootstrap claim is invalid or expired")
    family, _ = classify_os(payload.inventory)
    if family != record.expected_os_family:
        audit(db, f"bootstrap:{record.id}", "agent.package.os_mismatch", record.id, request, "blocked", {"expected": record.expected_os_family, "reported": family})
        db.commit()
        raise HTTPException(status_code=400, detail="This installer was generated for a different operating system")
    response = issue_agent_identity(
        agent_id=payload.agent_id,
        csr_pem=payload.csr_pem,
        inventory=payload.inventory,
        request=request,
        db=db,
        actor=f"bootstrap:{record.id}",
        initial_scan_created_by=record.created_by,
        allow_rotation=False,
    )
    record.used_at = now()
    audit(db, f"bootstrap:{record.id}", "agent.package.claim", payload.agent_id, request, detail={"label": record.label, "os_family": family})
    db.commit()
    return response


@app.post("/api/v1/enroll", status_code=201)
def enroll(payload: EnrollmentRequest, request: Request, db: Session = Depends(db_session)):
    record = db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == token_digest(payload.token))).scalar_one_or_none()
    if not record or record.uses >= record.max_uses or aware(record.expires_at) < now():
        raise HTTPException(status_code=401, detail="Enrollment token is invalid or expired")
    family, _ = classify_os(payload.inventory)
    if record.expected_os_family and record.expected_os_family != family:
        raise HTTPException(status_code=400, detail="Agent OS does not match enrollment policy")
    response = issue_agent_identity(
        agent_id=payload.agent_id,
        csr_pem=payload.csr_pem,
        inventory=payload.inventory,
        request=request,
        db=db,
        actor=f"agent:{payload.agent_id}",
        initial_scan_created_by=record.created_by,
        allow_rotation=True,
    )
    record.uses += 1
    db.commit()
    return response


@app.get("/api/v1/agent-server-ca")
def agent_server_ca():
    certificate, _ = read_agent_server_ca()
    return {"certificate": certificate}


def authenticate_agent_websocket(websocket: WebSocket, agent_id: str) -> Server:
    factory = SessionLocal
    if factory is None:
        raise HTTPException(status_code=503, detail="Database setup is required")
    with factory() as db:
        return verify_agent_identity(websocket.headers, "GET", websocket.url.path, db, agent_id, b"")


@app.websocket("/api/v1/agent/tunnel/control")
async def agent_tunnel_control(websocket: WebSocket, agent_id: str):
    try:
        authenticate_agent_websocket(websocket, agent_id)
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401, reason=str(exc.detail)[:120])
        return
    await websocket.accept()
    await tunnel_hub.register_control(agent_id, websocket)
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            if message.get("text"):
                try:
                    payload = json.loads(message["text"])
                except (TypeError, ValueError):
                    await websocket.close(code=4400, reason="Invalid control message")
                    break
                if payload.get("type") != "ready":
                    await websocket.close(code=4400, reason="Unsupported control message")
                    break
    except WebSocketDisconnect:
        pass
    finally:
        await tunnel_hub.unregister_control(agent_id, websocket)


@app.websocket("/api/v1/agent/tunnel/stream/{session_id}")
async def agent_tunnel_stream(websocket: WebSocket, session_id: str, agent_id: str):
    try:
        authenticate_agent_websocket(websocket, agent_id)
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401, reason=str(exc.detail)[:120])
        return
    await websocket.accept()
    await tunnel_hub.attach_stream(session_id, agent_id, websocket)


@app.get("/api/v1/agent/files/{transfer_id}")
async def agent_download_file(transfer_id: str, agent_id: str, request: Request, db: Session = Depends(db_session)):
    server = verify_agent(request, db, agent_id, b"")
    transfer = db.get(FileTransfer, transfer_id)
    if not transfer or transfer.server_id != server.id:
        raise HTTPException(status_code=404, detail="File transfer not found")
    if transfer.status not in {"queued", "transferring"} or not transfer.content_encrypted or not transfer.nonce:
        raise HTTPException(status_code=409, detail="File transfer is not available for delivery")
    if now() - aware(transfer.created_at) > timedelta(hours=settings.file_transfer_ttl_hours):
        transfer.status = "expired"
        transfer.content_encrypted = None
        transfer.nonce = ""
        audit(db, f"agent:{server.id}", "file.download.expired", transfer.id, request, "blocked")
        db.commit()
        raise HTTPException(status_code=410, detail="File transfer expired")
    try:
        content = decrypt_file(transfer.content_encrypted, transfer.nonce, transfer.id, transfer.server_id, transfer.sha256, settings.job_secret_key)
    except Exception as exc:
        audit(db, f"agent:{server.id}", "file.download.decrypt_failed", transfer.id, request, "failed")
        db.commit()
        raise HTTPException(status_code=500, detail="File transfer integrity validation failed") from exc
    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), transfer.sha256):
        raise HTTPException(status_code=500, detail="File transfer hash mismatch")
    transfer.status = "transferring"
    audit(db, f"agent:{server.id}", "file.download", transfer.id, request, detail={"filename": transfer.original_name, "size": transfer.size_bytes, "sha256": transfer.sha256})
    db.commit()
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Tram-Filename": transfer.original_name,
            "X-Tram-SHA256": transfer.sha256,
            "X-Tram-Size": str(transfer.size_bytes),
        },
    )


@app.post("/api/v1/agent/checkin")
async def agent_checkin(payload: CheckinRequest, request: Request, db: Session = Depends(db_session)):
    server = verify_agent(request, db, payload.agent_id, await request.body())
    expire_file_payloads(db)
    if payload.inventory:
        family, verification = classify_os(payload.inventory)
        if family != server.os_family:
            server.verified_os = False
            server.status = "quarantined"
            audit(db, f"agent:{server.id}", "agent.os_family.changed", server.id, request, "quarantined", {"old": server.os_family, "reported": family})
            db.commit()
            raise HTTPException(status_code=409, detail="OS family changed; manual verification required")
        server.name = payload.inventory.hostname
        server.os_name = payload.inventory.os_name
        server.os_version = payload.inventory.os_version
        server.distribution_id = payload.inventory.distribution_id
        server.architecture = payload.inventory.architecture
        server.inventory = payload.inventory.model_dump()
        server.ssh_host_key = payload.inventory.ssh_host_key
        server.verified_os = verification == "verified"
    server.agent_version = payload.agent_version
    server.last_seen = now()
    server.status = "online"
    server.cpu_percent = payload.metrics.cpu_percent
    server.memory_percent = payload.metrics.memory_percent
    server.disk_percent = payload.metrics.disk_percent
    server.uptime_seconds = payload.metrics.uptime_seconds
    if payload.metrics.pending_updates is not None:
        server.pending_updates = payload.metrics.pending_updates
    if payload.metrics.services_running is not None:
        server.services_running = payload.metrics.services_running
    server.alerts = payload.metrics.alerts
    supports_parallel_jobs = "active_job_ids" in payload.model_fields_set
    active_job_ids = payload.active_job_ids if supports_parallel_jobs else ([payload.active_job_id] if payload.active_job_id else [])
    if payload.active_job_id and active_job_ids and payload.active_job_id not in active_job_ids:
        raise HTTPException(status_code=409, detail="Agent primary active job is missing from the active job list")
    dispatched = db.execute(select(Job).where(Job.server_id == server.id, Job.status == "dispatched")).scalars().all()
    dispatched_by_id = {job.id: job for job in dispatched}
    for active_job_id in active_job_ids:
        if active_job_id not in dispatched_by_id:
            raise HTTPException(status_code=409, detail="Agent active job does not match control-plane state")
    for job in dispatched:
        if job.id in active_job_ids:
            continue
        job.status = "queued"
        job.started_at = None
        if job.action == "file.deliver":
            parameters = reveal_parameters(job.parameters)
            transfer = db.get(FileTransfer, str(parameters.get("transfer_id", "")))
            if transfer and transfer.server_id == server.id:
                transfer.status = "queued"
        audit(db, f"agent:{server.id}", "job.interrupted.requeued", job.id, request, detail={"action": job.action})

    jobs: list[Job] = []
    capacity = (MAX_CONCURRENT_AGENT_JOBS if supports_parallel_jobs else 1) - len(active_job_ids)
    if capacity > 0:
        active_mutation = any(dispatched_by_id[job_id].action not in PARALLEL_AGENT_READ_ACTIONS for job_id in active_job_ids)
        queued = db.execute(select(Job).where(Job.server_id == server.id, Job.status == "queued").order_by(Job.created_at).limit(100)).scalars().all()
        for queued_job in queued:
            is_read = queued_job.action in PARALLEL_AGENT_READ_ACTIONS
            if not is_read and active_mutation:
                continue
            jobs.append(queued_job)
            if not is_read:
                active_mutation = True
            if len(jobs) >= capacity:
                break
    for job in jobs:
        job.status = "dispatched"
        job.started_at = now()
        if job.action == "file.deliver":
            parameters = reveal_parameters(job.parameters)
            transfer = db.get(FileTransfer, str(parameters.get("transfer_id", "")))
            if transfer and transfer.server_id == server.id:
                transfer.status = "transferring"
    db.commit()
    return {"server_time": now().isoformat(), "checkin_interval_seconds": 5 if supports_parallel_jobs else 10, "inventory_interval_seconds": 1800, "max_concurrent_jobs": MAX_CONCURRENT_AGENT_JOBS if supports_parallel_jobs else 1, "jobs": [{"id": job.id, "action": job.action, "parameters": reveal_parameters(job.parameters)} for job in jobs]}


@app.post("/api/v1/agent/jobs/{job_id}/result")
async def agent_job_result(job_id: str, payload: JobResultRequest, request: Request, db: Session = Depends(db_session)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    server = verify_agent(request, db, job.server_id, await request.body())
    if job.status in {"succeeded", "failed"}:
        return {"accepted": True, "duplicate": True, "refresh_job_id": None, "refresh_job_ids": []}
    if job.status != "dispatched":
        raise HTTPException(status_code=409, detail="Job is not dispatched")
    refresh_actions = AUTO_REFRESH_ACTIONS.get(job.action, ()) if job.status == "dispatched" else ()
    job.status = payload.status
    job.exit_code = payload.exit_code
    job.output = payload.output
    job.finished_at = now()
    if job.action == "inventory.collect" and payload.status == "succeeded":
        try:
            inventory = Inventory.model_validate_json(payload.output)
            family, verification = classify_os(inventory)
            if family == server.os_family:
                server.name = inventory.hostname
                server.os_name = inventory.os_name
                server.os_version = inventory.os_version
                server.distribution_id = inventory.distribution_id
                server.architecture = inventory.architecture
                server.inventory = inventory.model_dump()
                server.ssh_host_key = inventory.ssh_host_key
                server.verified_os = verification == "verified"
        except (ValueError, TypeError):
            # Preserve the last known-good inventory when a signed endpoint
            # returns malformed refresh output. The job output remains visible
            # to operators for diagnosis.
            pass
    if job.action == "file.deliver":
        parameters = reveal_parameters(job.parameters)
        transfer = db.get(FileTransfer, str(parameters.get("transfer_id", "")))
        if transfer and transfer.server_id == server.id:
            transfer.status = "delivered" if payload.status == "succeeded" else "failed"
            transfer.delivered_at = now() if payload.status == "succeeded" else None
            transfer.content_encrypted = None
            transfer.nonce = ""
    audit(db, f"agent:{server.id}", f"job.{payload.status}", job.id, request, payload.status, {"action": job.action, "exit_code": payload.exit_code})
    db.flush()
    refresh_jobs: list[Job] = []
    for refresh_action in refresh_actions:
        refresh_parameters = {"limit": 500, "sources": configured_log_sources(db, server)} if refresh_action == "logs.read" else {}
        refresh_job = Job(
            server_id=server.id,
            action=refresh_action,
            parameters=refresh_parameters,
            reason=f"Tự động quét lại sau {job.action} {job.id[:8]}",
            status="queued",
            risk=SAFE_ACTIONS[refresh_action]["risk"],
            created_by=job.created_by,
        )
        db.add(refresh_job)
        db.flush()
        refresh_jobs.append(refresh_job)
        audit(
            db,
            f"agent:{server.id}",
            "job.auto_refresh",
            refresh_job.id,
            request,
            detail={"trigger_job_id": job.id, "trigger_action": job.action, "refresh_action": refresh_action},
        )
    db.commit()
    return {"accepted": True, "refresh_job_id": refresh_jobs[0].id if refresh_jobs else None, "refresh_job_ids": [item.id for item in refresh_jobs]}


@app.post("/api/v1/jobs", status_code=201)
def create_job(payload: JobCreateRequest, request: Request, user: User = Depends(current_user), db: Session = Depends(db_session)):
    policy = SAFE_ACTIONS.get(payload.action)
    if not policy:
        raise HTTPException(status_code=400, detail="Action is not allowlisted")
    required_permission = ACTION_PERMISSIONS.get(payload.action)
    if not required_permission or required_permission not in platform_role_permissions(db, user.role):
        raise HTTPException(status_code=403, detail="Role cannot execute this action")
    server = visible_server(db, user, payload.server_id)
    parameters = dict(payload.parameters)
    if payload.action == "logs.read":
        parameters = {"limit": 500, "sources": configured_log_sources(db, server)}
    validate_job_parameters(payload.action, parameters, server)
    job = Job(server_id=server.id, action=payload.action, parameters=protect_parameters(parameters), reason=payload.reason, status="queued", risk=policy["risk"], created_by=user.id)
    db.add(job)
    db.flush()
    audit(db, user.username, "job.create", job.id, request, detail={"server": server.name, "action": payload.action, "risk": job.risk, "execution": "direct"})
    db.commit()
    return {"id": job.id, "status": job.status, "risk": job.risk}


def bulk_task_json(task: BulkTask, db: Session, allowed_server_ids: set[str] | None = None) -> dict[str, Any]:
    rows = db.execute(
        select(BulkTaskItem, Job, Server)
        .join(Job, Job.id == BulkTaskItem.job_id)
        .join(Server, Server.id == BulkTaskItem.server_id)
        .where(BulkTaskItem.bulk_task_id == task.id)
        .order_by(Server.name)
    ).all()
    statuses: dict[str, int] = {}
    items: list[dict[str, Any]] = []
    for _, job, server in rows:
        if allowed_server_ids is not None and server.id not in allowed_server_ids:
            continue
        statuses[job.status] = statuses.get(job.status, 0) + 1
        items.append({
            "serverId": server.id,
            "serverName": server.name,
            "osFamily": server.os_family,
            "jobId": job.id,
            "status": job.status,
            "exitCode": job.exit_code,
        })
    return {
        "id": task.id,
        "action": task.action,
        "osFamily": task.os_family,
        "targetCount": len(items) if allowed_server_ids is not None else task.target_count,
        "summary": task.summary or {},
        "reason": task.reason,
        "createdAt": aware(task.created_at).isoformat(),
        "statuses": statuses,
        "items": items,
    }


@app.post("/api/v1/bulk-tasks", status_code=201)
def create_bulk_task(payload: BulkTaskCreateRequest, request: Request, user: User = Depends(current_user), db: Session = Depends(db_session)):
    policy = SAFE_ACTIONS.get(payload.action)
    permission = ACTION_PERMISSIONS.get(payload.action)
    if not policy or not permission or permission not in platform_role_permissions(db, user.role):
        raise HTTPException(status_code=403, detail="Role cannot execute this bulk action")
    server_ids = list(dict.fromkeys(payload.server_ids))
    if len(server_ids) != len(payload.server_ids):
        raise HTTPException(status_code=422, detail="Duplicate target servers are not allowed")
    allowed_server_ids = visible_server_ids(db, user)
    if not set(server_ids).issubset(allowed_server_ids):
        raise HTTPException(status_code=404, detail="One or more target servers were not found")
    servers = db.execute(select(Server).where(Server.id.in_(server_ids))).scalars().all()
    servers_by_id = {server.id: server for server in servers}
    if len(servers_by_id) != len(server_ids):
        raise HTTPException(status_code=404, detail="One or more target servers were not found")
    ordered_servers = [servers_by_id[server_id] for server_id in server_ids]
    if any(server.os_family != payload.os_family for server in ordered_servers):
        raise HTTPException(status_code=422, detail="All target servers must belong to the selected Windows or Linux fleet")

    requested = dict(payload.parameters)
    if payload.action == "user.create":
        allowed = {"username", "password", "is_admin"}
        if set(requested) != allowed or not isinstance(requested.get("is_admin"), bool):
            raise HTTPException(status_code=422, detail="Common user parameters are incomplete")
        job_parameters = {
            "username": requested["username"],
            "password": requested["password"],
            "groups": [],
            "is_admin": requested["is_admin"],
        }
        summary = {"username": str(requested["username"]), "isAdmin": requested["is_admin"]}
    else:
        job_parameters = requested
        summary = {key: value for key, value in requested.items() if key not in {"password", "secret", "token"}}

    for server in ordered_servers:
        validate_job_parameters(payload.action, job_parameters, server)

    task = BulkTask(
        action=payload.action,
        os_family=payload.os_family,
        target_count=len(ordered_servers),
        summary=summary,
        reason=payload.reason,
        created_by=user.id,
    )
    db.add(task)
    db.flush()
    for server in ordered_servers:
        job = Job(
            server_id=server.id,
            action=payload.action,
            parameters=protect_parameters(job_parameters),
            reason=payload.reason,
            status="queued",
            risk=policy["risk"],
            created_by=user.id,
        )
        db.add(job)
        db.flush()
        db.add(BulkTaskItem(bulk_task_id=task.id, server_id=server.id, job_id=job.id))
        audit(db, user.username, "job.create", job.id, request, detail={"server": server.name, "action": payload.action, "risk": job.risk, "execution": "bulk", "bulk_task_id": task.id})
    audit(db, user.username, "bulk_task.create", task.id, request, detail={"action": payload.action, "os_family": payload.os_family, "target_count": len(ordered_servers), "execution": "direct"})
    db.commit()
    return bulk_task_json(task, db)


@app.get("/api/v1/bulk-tasks")
def list_bulk_tasks(os_family: Literal["windows", "linux"] | None = None, _: User = Depends(require_permission("servers.view")), db: Session = Depends(db_session)):
    query = select(BulkTask).order_by(BulkTask.created_at.desc()).limit(100)
    if os_family:
        query = query.where(BulkTask.os_family == os_family)
    allowed = visible_server_ids(db, _)
    items = [bulk_task_json(task, db, allowed) for task in db.execute(query).scalars().all()]
    return {"items": [item for item in items if item["items"]]}


@app.get("/api/v1/jobs")
def list_jobs(user: User = Depends(require_permission("servers.view")), db: Session = Depends(db_session)):
    jobs = db.execute(select(Job).where(Job.server_id.in_(visible_server_ids(db, user))).order_by(Job.created_at.desc()).limit(200)).scalars().all()
    return {"items": [job_json(job, include_output=can_view_job_output(user, job.action, db)) for job in jobs]}


@app.get("/api/v1/audit")
def list_audit(before: datetime | None = None, _: User = Depends(require_permission("audit.view")), db: Session = Depends(db_session)):
    query = select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(500)
    if before is not None:
        query = query.where(AuditEvent.occurred_at < aware(before))
    events = db.execute(query).scalars().all()
    return {
        "items": [
            {
                "id": item.id,
                "occurredAt": aware(item.occurred_at).isoformat(),
                "actor": item.actor,
                "action": item.action,
                "target": item.target,
                "result": item.result,
                "sourceIp": item.source_ip,
                "detail": item.detail or {},
                "hash": item.event_hash,
                "previousHash": item.previous_hash,
            }
            for item in events
        ],
        "nextBefore": aware(events[-1].occurred_at).isoformat() if len(events) == 500 else None,
        "retentionDays": settings.audit_retention_days,
    }


@app.get("/api/v1/sessions")
def list_sessions(user: User = Depends(require_permission("recordings.view")), db: Session = Depends(db_session)):
    rows = db.execute(select(RemoteSession, Server.name).join(Server, Server.id == RemoteSession.server_id).where(RemoteSession.server_id.in_(visible_server_ids(db, user))).order_by(RemoteSession.started_at.desc()).limit(200)).all()
    items = []
    for item, server_name in rows:
        paths, recording_status = recording_probe(item.id)
        path = paths[0] if paths else None
        items.append({"id": item.id, "serverId": item.server_id, "serverName": server_name, "protocol": item.protocol, "username": item.remote_username, "createdBy": item.created_by, "status": item.status, "recordingName": item.recording_name, "recordingAvailable": path is not None, "recordingSizeBytes": path.stat().st_size if path else 0, "recordingStatus": recording_status, "startedAt": aware(item.started_at).isoformat(), "finishedAt": aware(item.finished_at).isoformat() if item.finished_at else None})
    return {"items": items}


def recording_probe(session_id: str, include_typescript: bool = False) -> tuple[list[Path], str]:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", session_id):
        return [], "invalid_session"
    try:
        root = Path(settings.recording_root).resolve(strict=True)
    except FileNotFoundError:
        return [], "root_missing"
    except (OSError, RuntimeError):
        return [], "permission_denied"
    if not root.is_dir():
        return [], "root_invalid"
    try:
        candidates = list(root.iterdir())
    except PermissionError:
        return [], "permission_denied"
    except OSError:
        return [], "root_unreadable"
    matches: list[Path] = []
    saw_empty = False
    saw_denied = False
    for candidate in candidates:
        name = candidate.name
        if not (name == session_id or (name.startswith(session_id) and len(name) > len(session_id) and name[len(session_id)] in "-._")):
            continue
        try:
            resolved = candidate.resolve(strict=True)
            if resolved.parent != root or not resolved.is_file():
                continue
            if resolved.stat().st_size <= 0:
                saw_empty = True
                continue
        except PermissionError:
            saw_denied = True
            continue
        except OSError:
            continue
        if not include_typescript and resolved.name.endswith(".typescript"):
            continue
        matches.append(resolved)
    ordered = sorted(matches, key=lambda item: item.stat().st_mtime, reverse=True)
    if ordered:
        return ordered, "available"
    if saw_denied:
        return [], "permission_denied"
    if saw_empty:
        return [], "empty"
    return [], "not_found"


def recording_files(session_id: str, include_typescript: bool = False) -> list[Path]:
    return recording_probe(session_id, include_typescript)[0]


def recording_file(session_id: str) -> Path | None:
    candidates = recording_files(session_id)
    return candidates[0] if candidates else None


def recording_deletion_json(item: RecordingDeletionRequest, db: Session) -> dict[str, Any]:
    sessions = db.execute(select(RemoteSession, Server.name).join(Server, Server.id == RemoteSession.server_id).where(RemoteSession.id.in_(item.session_ids))).all()
    labels = {session.id: f"{server_name} · {session.protocol.upper()} · {aware(session.started_at).isoformat()}" for session, server_name in sessions}
    return {
        "id": item.id,
        "sessionIds": item.session_ids,
        "sessions": [{"id": session_id, "label": labels.get(session_id, session_id)} for session_id in item.session_ids],
        "reason": item.reason,
        "status": item.status,
        "requestedBy": item.requested_by,
        "requestedByUsername": item.requested_by_username,
        "approvedBy": item.approved_by,
        "approvedByUsername": item.approved_by_username,
        "createdAt": aware(item.created_at).isoformat(),
        "approvedAt": aware(item.approved_at).isoformat() if item.approved_at else None,
        "completedAt": aware(item.completed_at).isoformat() if item.completed_at else None,
        "error": item.error,
    }


@app.get("/api/v1/settings/recording-retention")
def get_recording_retention(_: User = Depends(require_permission("recordings.delete")), db: Session = Depends(db_session)):
    return read_recording_retention(db)


@app.put("/api/v1/settings/recording-retention")
def update_recording_retention(payload: RecordingRetentionRequest, request: Request, user: User = Depends(require_permission("recordings.delete")), db: Session = Depends(db_session)):
    previous = read_recording_retention(db)
    config = payload.model_dump()
    db.merge(SystemSetting(key=RECORDING_RETENTION_KEY, value=json.dumps(config, separators=(",", ":"))))
    db.flush()
    result = prune_recording_files(db) if payload.enabled else None
    audit(
        db,
        user.username,
        "settings.recording_retention.update",
        "recordings",
        request,
        detail={"previous": {"enabled": previous["enabled"], "days": previous["days"]}, "current": config, "immediate_prune": result},
    )
    db.commit()
    return read_recording_retention(db)


@app.get("/api/v1/recording-deletion-requests")
def list_recording_deletion_requests(_: User = Depends(require_permission("recordings.delete")), db: Session = Depends(db_session)):
    rows = db.execute(select(RecordingDeletionRequest).order_by(RecordingDeletionRequest.created_at.desc()).limit(100)).scalars().all()
    return {"items": [recording_deletion_json(item, db) for item in rows]}


@app.post("/api/v1/recording-deletion-requests", status_code=201)
def create_recording_deletion_request(payload: RecordingDeletionCreateRequest, request: Request, user: User = Depends(require_permission("recordings.delete")), db: Session = Depends(db_session)):
    session_ids = list(dict.fromkeys(payload.session_ids))
    if len(session_ids) != len(payload.session_ids) or any(not re.fullmatch(r"[0-9a-fA-F-]{36}", item) for item in session_ids):
        raise HTTPException(status_code=400, detail="Danh sách recording không hợp lệ hoặc bị trùng")
    sessions = db.execute(select(RemoteSession).where(RemoteSession.id.in_(session_ids))).scalars().all()
    if len(sessions) != len(session_ids):
        raise HTTPException(status_code=404, detail="Có session không còn tồn tại")
    unavailable = [item.id for item in sessions if recording_file(item.id) is None]
    if unavailable:
        raise HTTPException(status_code=409, detail="Có recording chưa sẵn sàng; hãy tải lại danh sách")
    pending = db.execute(select(RecordingDeletionRequest).where(RecordingDeletionRequest.status.in_(["pending", "deleting"]))).scalars().all()
    if any(set(item.session_ids).intersection(session_ids) for item in pending):
        raise HTTPException(status_code=409, detail="Một recording đã nằm trong yêu cầu xóa đang chờ duyệt")
    deletion = RecordingDeletionRequest(session_ids=session_ids, reason=payload.reason.strip(), requested_by=user.id, requested_by_username=user.username)
    db.add(deletion)
    db.flush()
    audit(db, user.username, "session.recording.delete.request", deletion.id, request, detail={"session_ids": session_ids, "count": len(session_ids)})
    db.commit()
    return recording_deletion_json(deletion, db)


@app.post("/api/v1/recording-deletion-requests/{deletion_id}/approve")
def approve_recording_deletion_request(deletion_id: str, request: Request, user: User = Depends(require_permission("recordings.delete")), db: Session = Depends(db_session)):
    deletion = db.get(RecordingDeletionRequest, deletion_id)
    if not deletion:
        raise HTTPException(status_code=404, detail="Yêu cầu xóa recording không tồn tại")
    if deletion.requested_by == user.id:
        raise HTTPException(status_code=409, detail="Người tạo yêu cầu không được tự duyệt; cần quản trị viên thứ hai")
    claimed_at = now()
    result = db.execute(update(RecordingDeletionRequest).where(RecordingDeletionRequest.id == deletion_id, RecordingDeletionRequest.status == "pending").values(status="deleting", approved_by=user.id, approved_by_username=user.username, approved_at=claimed_at))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Yêu cầu này không còn ở trạng thái chờ duyệt")
    db.commit()
    deletion = db.get(RecordingDeletionRequest, deletion_id)
    deleted_files: list[str] = []
    try:
        for session_id in deletion.session_ids:
            for path in recording_files(session_id, include_typescript=True):
                path.unlink()
                deleted_files.append(path.name)
        deletion.status = "deleted"
        deletion.completed_at = now()
        audit(db, user.username, "session.recording.delete.approve", deletion.id, request, detail={"requested_by": deletion.requested_by_username, "session_ids": deletion.session_ids, "files_deleted": len(deleted_files)})
        db.commit()
    except OSError as exc:
        deletion.status = "failed"
        deletion.error = str(exc)[:2000]
        deletion.completed_at = now()
        audit(db, user.username, "session.recording.delete.approve", deletion.id, request, result="failed", detail={"files_deleted": len(deleted_files), "error": deletion.error})
        db.commit()
        raise HTTPException(status_code=500, detail="Không thể xóa toàn bộ recording; xem nhật ký kiểm toán") from exc
    return recording_deletion_json(deletion, db)


@app.get("/api/v1/sessions/{session_id}/recording")
def read_recording(session_id: str, request: Request, user: User = Depends(require_permission("recordings.view")), db: Session = Depends(db_session)):
    session = db.get(RemoteSession, session_id)
    if not session or session.server_id not in visible_server_ids(db, user):
        raise HTTPException(status_code=404, detail="Session not found")
    path = recording_file(session.id)
    if not path:
        raise HTTPException(status_code=404, detail="Recording chưa sẵn sàng hoặc phiên chưa phát sinh hình ảnh")
    audit(db, user.username, "session.recording.view", session.id, request)
    db.commit()
    return FileResponse(path, media_type="application/octet-stream", filename=f"{session.id}.guac", content_disposition_type="inline", headers={"Cache-Control": "private, no-store"})


@app.post("/api/v1/sessions/launch")
async def launch_session(payload: SessionLaunchRequest, request: Request, user: User = Depends(require_permission("sessions.launch")), db: Session = Depends(db_session)):
    server = visible_server(db, user, payload.server_id)
    if payload.protocol == "rdp" and server.os_family != "windows":
        raise HTTPException(status_code=400, detail="RDP is reserved for Windows servers")
    if payload.protocol == "ssh" and server.os_family != "linux":
        raise HTTPException(status_code=400, detail="SSH is reserved for Linux servers")
    if not tunnel_hub.is_online(server.id):
        raise HTTPException(status_code=409, detail="Kênh tunnel mTLS của agent đang offline; hệ thống không fallback sang 22/3389 trực tiếp")
    session_id = str(uuid.uuid4())
    try:
        relay_port = await tunnel_hub.create_listener(session_id, server.id, payload.protocol)
    except (ConnectionError, OSError) as exc:
        target = "127.0.0.1:22 (sshd)" if payload.protocol == "ssh" else "127.0.0.1:3389 (Remote Desktop)"
        raise HTTPException(
            status_code=409,
            detail=f"Agent không thể chuẩn bị kết nối tới {target}. Kiểm tra dịch vụ local và log Agent; không mở trực tiếp cổng quản trị ra mạng.",
        ) from exc
    common = {"hostname": settings.tunnel_relay_host, "port": str(relay_port), "username": payload.username, "password": payload.password, "recording-path": settings.recording_root, "create-recording-path": "true", "recording-name": f"{session_id}-${{GUAC_USERNAME}}-${{GUAC_DATE}}-${{GUAC_TIME}}", "recording-exclude-output": "false", "recording-exclude-mouse": "false", "recording-exclude-touch": "false", "disable-copy": "true", "disable-paste": "true"}
    if payload.protocol == "ssh":
        common.update({"typescript-path": settings.recording_root, "create-typescript-path": "true", "typescript-name": f"{session_id}.typescript", "enable-sftp": "false", "sftp-disable-upload": "true", "sftp-disable-download": "true"})
        known_host = guacamole_ssh_host_key(settings.tunnel_relay_host, relay_port, server.ssh_host_key)
        if known_host:
            common["host-key"] = known_host
    else:
        fingerprint = guacamole_rdp_certificate_fingerprint(
            (server.inventory or {}).get("extra", {}).get("rdp_certificate_fingerprint")
        )
        if not fingerprint:
            await tunnel_hub.cancel(session_id, "rdp-certificate-missing")
            raise HTTPException(status_code=409, detail="Agent chưa cung cấp fingerprint certificate RDP; cấu hình certificate RDP rồi đồng bộ inventory")
        common.update({"security": "nla", "ignore-cert": "false", "cert-fingerprints": fingerprint, "enable-drive": "false", "disable-upload": "true", "disable-download": "true", "enable-printing": "false", "width": str(payload.width), "height": str(payload.height), "resize-method": "display-update"})
    try:
        guac_payload = {"username": user.username, "expires": int((now() + timedelta(minutes=2)).timestamp() * 1000), "connections": {server.name: {"protocol": payload.protocol, "parameters": common}}}
        encrypted = encrypt_guacamole_json(guac_payload)
        db.add(RemoteSession(id=session_id, server_id=server.id, protocol=payload.protocol, remote_username=payload.username, created_by=user.username, status="waiting", recording_name=f"{session_id}-${{GUAC_USERNAME}}-${{GUAC_DATE}}-${{GUAC_TIME}}"))
        audit(db, user.username, f"session.{payload.protocol}.launch", server.id, request, detail={"session_id": session_id, "transport": "agent-mtls-tunnel", "target_port": 22 if payload.protocol == "ssh" else 3389, "recording": True, "clipboard": "disabled", "native_file_transfer": "disabled"})
        db.commit()
    except Exception:
        await tunnel_hub.cancel(session_id, "launch-failed")
        raise
    return {
        "sessionId": session_id,
        "url": guacamole_launch_url(settings.guacamole_url, server.name, encrypted),
        "expiresIn": 120,
        "recording": True,
    }
