from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import jwt
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./tram-ops.db"
    jwt_secret: str = "change-me"
    jwt_issuer: str = "tram-van-hanh"
    jwt_ttl_minutes: int = 480
    bootstrap_admin_user: str = "admin"
    bootstrap_admin_password: str = ""
    agent_ca_cert: str = "/run/secrets/agent-ca.crt"
    agent_ca_key: str = "/run/secrets/agent-ca.key"
    agent_cert_days: int = 90
    guacamole_url: str = "/guacamole"
    guacamole_json_secret: str = ""
    job_secret_key: str = ""
    allowed_origins: str = ""
    recording_root: str = "/recordings"


settings = Settings()
password_hasher = PasswordHasher()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


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


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="pending_approval", index=True)
    risk: Mapped[str] = mapped_column(String(20), default="medium")
    created_by: Mapped[str] = mapped_column(String(36))
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[str] = mapped_column(Text, default="")
    server: Mapped[Server] = relationship(back_populates="jobs")


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


class LoginRequest(BaseModel):
    username: str
    password: str


class EnrollmentTokenRequest(BaseModel):
    label: str = ""
    expected_os_family: Literal["windows", "linux"] | None = None
    expires_hours: int = Field(default=24, ge=1, le=168)
    max_uses: int = Field(default=1, ge=1, le=1000)


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
    inventory: Inventory | None = None
    metrics: Metrics


class JobCreateRequest(BaseModel):
    server_id: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2000)
    require_approval: bool = True


class JobResultRequest(BaseModel):
    status: Literal["succeeded", "failed"]
    exit_code: int
    output: str = Field(default="", max_length=100_000)


class SessionLaunchRequest(BaseModel):
    server_id: str
    protocol: Literal["ssh", "rdp"]
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    width: int = Field(default=1440, ge=800, le=7680)
    height: int = Field(default=900, ge=600, le=4320)


SAFE_ACTIONS: dict[str, dict[str, Any]] = {
    "inventory.collect": {"roles": {"admin", "operator"}, "risk": "low", "approval": False},
    "service.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low", "approval": False},
    "service.restart": {"roles": {"admin", "operator"}, "risk": "medium", "approval": True},
    "service.start": {"roles": {"admin", "operator"}, "risk": "medium", "approval": True},
    "service.stop": {"roles": {"admin", "operator"}, "risk": "high", "approval": True},
    "user.create": {"roles": {"admin", "operator"}, "risk": "high", "approval": True},
    "user.disable": {"roles": {"admin", "operator"}, "risk": "high", "approval": True},
    "group.create": {"roles": {"admin", "operator"}, "risk": "medium", "approval": True},
    "user.add_group": {"roles": {"admin", "operator"}, "risk": "high", "approval": True},
    "patch.scan": {"roles": {"admin", "operator", "viewer"}, "risk": "low", "approval": False},
    "patch.install_security": {"roles": {"admin", "operator"}, "risk": "high", "approval": True},
    "logs.read": {"roles": {"admin", "operator", "viewer", "auditor"}, "risk": "low", "approval": False},
    "process.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low", "approval": False},
    "firewall.list": {"roles": {"admin", "operator", "viewer"}, "risk": "low", "approval": False},
    "system.reboot": {"roles": {"admin", "operator"}, "risk": "critical", "approval": True},
}


app = FastAPI(title="Trạm Vận Hành API", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
origins = [item.strip() for item in settings.allowed_origins.split(",") if item.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def db_session():
    session = SessionLocal()
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


def audit(db: Session, actor: str, action: str, target: str, request: Request | None = None, result: str = "success", detail: dict[str, Any] | None = None) -> None:
    previous = db.execute(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(1)).scalar_one_or_none()
    occurred = now()
    payload = json.dumps({"occurred_at": occurred.isoformat(), "actor": actor, "action": action, "target": target, "result": result, "detail": detail or {}}, sort_keys=True, separators=(",", ":"))
    previous_hash = previous.event_hash if previous else "0" * 64
    event_hash = hashlib.sha256((previous_hash + payload).encode()).hexdigest()
    db.add(AuditEvent(occurred_at=occurred, actor=actor, action=action, target=target, result=result, source_ip=client_ip(request) if request else "", detail=detail or {}, previous_hash=previous_hash, event_hash=event_hash))


def issue_jwt(user: User) -> str:
    timestamp = now()
    return jwt.encode({"sub": user.id, "username": user.username, "role": user.role, "iss": settings.jwt_issuer, "iat": timestamp, "exp": timestamp + timedelta(minutes=settings.jwt_ttl_minutes)}, settings.jwt_secret, algorithm="HS256")


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


def require_role(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permission")
        return user
    return dependency


def verify_agent(request: Request, db: Session, agent_id: str) -> Server:
    fingerprint = request.headers.get("x-agent-cert-fingerprint", "").replace(":", "").lower()
    subject = request.headers.get("x-agent-cert-subject", "")
    if not fingerprint:
        raise HTTPException(status_code=401, detail="mTLS client certificate required")
    server = db.get(Server, agent_id)
    if not server or not server.cert_fingerprint or not hmac.compare_digest(server.cert_fingerprint, fingerprint):
        raise HTTPException(status_code=401, detail="Unknown agent certificate")
    if f"CN={agent_id}" not in subject and f"CN = {agent_id}" not in subject:
        raise HTTPException(status_code=401, detail="Certificate subject mismatch")
    return server


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
    return {"id": server.id, "name": server.name, "osFamily": server.os_family, "os": server.os_name, "version": server.os_version, "address": server.address, "environment": server.environment, "health": health, "agentVersion": server.agent_version, "lastSeen": relative, "cpu": round(server.cpu_percent), "memory": round(server.memory_percent), "disk": round(server.disk_percent), "uptime": f"{days} ngày {hours} giờ", "updates": server.pending_updates, "alerts": server.alerts, "services": server.services_running, "owner": server.owner, "tags": server.tags or [], "verifiedOS": server.verified_os}


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


@app.on_event("startup")
def startup() -> None:
    job_fernet()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        exists = db.execute(select(User).limit(1)).scalar_one_or_none()
        if not exists:
            if not settings.bootstrap_admin_password or len(settings.bootstrap_admin_password) < 14:
                raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 14 characters on first start")
            db.add(User(username=settings.bootstrap_admin_user, display_name="Platform Administrator", password_hash=password_hasher.hash(settings.bootstrap_admin_password), role="admin"))
            db.commit()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(db_session)):
    user = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    valid = False
    if user:
        try:
            valid = password_hasher.verify(user.password_hash, payload.password)
        except Exception:
            valid = False
    if not user or not valid or not user.enabled:
        audit(db, payload.username, "auth.login", "dashboard", request, "denied")
        db.commit()
        raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không đúng")
    audit(db, user.username, "auth.login", "dashboard", request)
    db.commit()
    return {"access_token": issue_jwt(user), "token_type": "bearer", "expires_in": settings.jwt_ttl_minutes * 60, "user": {"username": user.username, "displayName": user.display_name, "role": user.role}}


@app.get("/api/v1/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "displayName": user.display_name, "role": user.role}


@app.get("/api/v1/servers")
def list_servers(os_family: Literal["windows", "linux"] | None = None, _: User = Depends(current_user), db: Session = Depends(db_session)):
    query = select(Server).order_by(Server.os_family, Server.name)
    if os_family:
        query = query.where(Server.os_family == os_family)
    return {"items": [server_json(item) for item in db.execute(query).scalars().all()]}


@app.get("/api/v1/servers/{server_id}")
def get_server(server_id: str, _: User = Depends(current_user), db: Session = Depends(db_session)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return {**server_json(server), "inventory": server.inventory}


@app.post("/api/v1/enrollment-tokens", status_code=201)
def create_enrollment_token(payload: EnrollmentTokenRequest, request: Request, user: User = Depends(require_role("admin")), db: Session = Depends(db_session)):
    raw = "tvo_" + secrets.token_urlsafe(32)
    record = EnrollmentToken(token_hash=token_digest(raw), label=payload.label, expected_os_family=payload.expected_os_family, max_uses=payload.max_uses, expires_at=now() + timedelta(hours=payload.expires_hours), created_by=user.id)
    db.add(record)
    audit(db, user.username, "enrollment.token.create", record.id, request, detail={"label": payload.label, "expected_os_family": payload.expected_os_family, "max_uses": payload.max_uses})
    db.commit()
    return {"id": record.id, "token": raw, "expiresAt": record.expires_at.isoformat(), "note": "Token is shown once"}


@app.post("/api/v1/enroll", status_code=201)
def enroll(payload: EnrollmentRequest, request: Request, db: Session = Depends(db_session)):
    try:
        uuid.UUID(payload.agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="agent_id must be a UUID") from exc
    record = db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == token_digest(payload.token))).scalar_one_or_none()
    if not record or record.uses >= record.max_uses or aware(record.expires_at) < now():
        raise HTTPException(status_code=401, detail="Enrollment token is invalid or expired")
    family, verification = classify_os(payload.inventory)
    if record.expected_os_family and record.expected_os_family != family:
        raise HTTPException(status_code=400, detail="Agent OS does not match enrollment policy")
    cert_pem, fingerprint, cert_expires = sign_agent_csr(payload.csr_pem, payload.agent_id)
    server = db.get(Server, payload.agent_id)
    if server and server.cert_fingerprint:
        raise HTTPException(status_code=409, detail="Agent is already enrolled")
    remote_protocol = "rdp" if family == "windows" else "ssh"
    server = server or Server(id=payload.agent_id, name=payload.inventory.hostname, os_family=family, os_name=payload.inventory.os_name)
    server.name = payload.inventory.hostname
    server.os_family = family
    server.os_name = payload.inventory.os_name
    server.os_version = payload.inventory.os_version
    server.distribution_id = payload.inventory.distribution_id
    server.architecture = payload.inventory.architecture
    server.address = next((address for address in payload.inventory.addresses if not address.startswith("127.") and address != "::1"), "")
    server.agent_version = payload.inventory.agent_version
    server.cert_fingerprint = fingerprint
    server.cert_expires_at = cert_expires
    server.last_seen = now()
    server.status = "online"
    server.inventory = payload.inventory.model_dump()
    server.ssh_host_key = payload.inventory.ssh_host_key
    server.remote_protocol = remote_protocol
    server.verified_os = verification == "verified"
    db.add(server)
    record.uses += 1
    audit(db, f"agent:{payload.agent_id}", "agent.enroll", payload.agent_id, request, detail={"os_family": family, "distribution": payload.inventory.distribution_id, "verified": server.verified_os})
    db.commit()
    return {"agent_id": payload.agent_id, "certificate": cert_pem, "ca_certificate": Path(settings.agent_ca_cert).read_text(), "expires_at": cert_expires.isoformat(), "os_family": family, "category": "Windows" if family == "windows" else "Linux", "agent_endpoint": "https://" + request.url.hostname + ":9443/api/v1/agent"}


@app.post("/api/v1/agent/checkin")
def agent_checkin(payload: CheckinRequest, request: Request, db: Session = Depends(db_session)):
    server = verify_agent(request, db, payload.agent_id)
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
    jobs = db.execute(select(Job).where(Job.server_id == server.id, Job.status == "queued").order_by(Job.created_at).limit(10)).scalars().all()
    for job in jobs:
        job.status = "dispatched"
        job.started_at = now()
    db.commit()
    return {"server_time": now().isoformat(), "inventory_interval_seconds": 1800, "jobs": [{"id": job.id, "action": job.action, "parameters": reveal_parameters(job.parameters)} for job in jobs]}


@app.post("/api/v1/agent/jobs/{job_id}/result")
def agent_job_result(job_id: str, payload: JobResultRequest, request: Request, db: Session = Depends(db_session)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    server = verify_agent(request, db, job.server_id)
    job.status = payload.status
    job.exit_code = payload.exit_code
    job.output = payload.output
    job.finished_at = now()
    audit(db, f"agent:{server.id}", f"job.{payload.status}", job.id, request, payload.status, {"action": job.action, "exit_code": payload.exit_code})
    db.commit()
    return {"accepted": True}


@app.post("/api/v1/jobs", status_code=201)
def create_job(payload: JobCreateRequest, request: Request, user: User = Depends(require_role("admin", "operator", "viewer")), db: Session = Depends(db_session)):
    policy = SAFE_ACTIONS.get(payload.action)
    if not policy:
        raise HTTPException(status_code=400, detail="Action is not allowlisted")
    if user.role not in policy["roles"]:
        raise HTTPException(status_code=403, detail="Role cannot execute this action")
    server = db.get(Server, payload.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    requires = bool(policy["approval"] or payload.require_approval)
    job = Job(server_id=server.id, action=payload.action, parameters=protect_parameters(payload.parameters), reason=payload.reason, status="pending_approval" if requires else "queued", risk=policy["risk"], created_by=user.id)
    db.add(job)
    db.flush()
    audit(db, user.username, "job.create", job.id, request, detail={"server": server.name, "action": payload.action, "risk": job.risk, "approval": requires})
    db.commit()
    return {"id": job.id, "status": job.status, "risk": job.risk}


@app.post("/api/v1/jobs/{job_id}/approve")
def approve_job(job_id: str, request: Request, user: User = Depends(require_role("admin")), db: Session = Depends(db_session)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "pending_approval":
        raise HTTPException(status_code=409, detail="Job is not awaiting approval")
    if job.created_by == user.id:
        raise HTTPException(status_code=409, detail="Four-eyes policy: creator cannot approve own job")
    job.status = "queued"
    job.approved_by = user.id
    job.approved_at = now()
    audit(db, user.username, "job.approve", job.id, request)
    db.commit()
    return {"id": job.id, "status": job.status}


@app.get("/api/v1/jobs")
def list_jobs(_: User = Depends(current_user), db: Session = Depends(db_session)):
    jobs = db.execute(select(Job).order_by(Job.created_at.desc()).limit(200)).scalars().all()
    return {"items": [{"id": job.id, "serverId": job.server_id, "action": job.action, "status": job.status, "risk": job.risk, "reason": job.reason, "createdAt": aware(job.created_at).isoformat()} for job in jobs]}


@app.get("/api/v1/audit")
def list_audit(_: User = Depends(require_role("admin", "auditor")), db: Session = Depends(db_session)):
    events = db.execute(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(500)).scalars().all()
    return {"items": [{"id": item.id, "occurredAt": aware(item.occurred_at).isoformat(), "actor": item.actor, "action": item.action, "target": item.target, "result": item.result, "sourceIp": item.source_ip, "hash": item.event_hash, "previousHash": item.previous_hash} for item in events]}


@app.post("/api/v1/sessions/launch")
def launch_session(payload: SessionLaunchRequest, request: Request, user: User = Depends(require_role("admin", "operator")), db: Session = Depends(db_session)):
    server = db.get(Server, payload.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    if payload.protocol == "rdp" and server.os_family != "windows":
        raise HTTPException(status_code=400, detail="RDP is reserved for Windows servers")
    if payload.protocol == "ssh" and server.os_family != "linux":
        raise HTTPException(status_code=400, detail="SSH is reserved for Linux servers")
    session_id = str(uuid.uuid4())
    common = {"hostname": server.address, "port": "3389" if payload.protocol == "rdp" else "22", "username": payload.username, "password": payload.password, "recording-path": settings.recording_root, "create-recording-path": "true", "recording-name": f"{session_id}-${{GUAC_USERNAME}}-${{GUAC_DATE}}-${{GUAC_TIME}}"}
    if payload.protocol == "ssh":
        common.update({"typescript-path": settings.recording_root, "create-typescript-path": "true", "typescript-name": f"{session_id}.typescript"})
        if server.ssh_host_key:
            common["host-key"] = server.ssh_host_key
    else:
        common.update({"security": "nla", "ignore-cert": "false", "width": str(payload.width), "height": str(payload.height), "resize-method": "display-update"})
    guac_payload = {"username": user.username, "expires": int((now() + timedelta(minutes=2)).timestamp() * 1000), "connections": {server.name: {"protocol": payload.protocol, "parameters": common}}}
    encrypted = encrypt_guacamole_json(guac_payload)
    audit(db, user.username, f"session.{payload.protocol}.launch", server.id, request, detail={"session_id": session_id, "recording": True})
    db.commit()
    return {"sessionId": session_id, "url": f"{settings.guacamole_url}/?data={quote(encrypted)}", "expiresIn": 120, "recording": True}
