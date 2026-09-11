"""Validated connection metadata and write-only initial authentication."""
from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


class InitialTargetCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=1024)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid username")
        return value


class ManagedTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=100, pattern=r"^[\w .-]+$")
    kind: Literal["network", "web"]
    address: str = Field(default="", max_length=120)
    port: int | None = Field(default=None, ge=1, le=65535)
    url: str = Field(default="", max_length=2048)
    web_allowed_origins: list[str] = Field(default_factory=list, max_length=16)
    # Retired checkbox: accept legacy rows/forms, but do not persist it again.
    web_ignore_https_errors: bool = Field(default=False, strict=True, exclude=True, repr=False)
    ssh_host_key: str = Field(default="", max_length=2048)
    # Accept old persisted metadata/stale forms, but never use or re-serialize
    # the retired opt-in. All registered SSH targets now negotiate automatically.
    ssh_legacy_compatibility: bool = Field(default=False, strict=True, exclude=True, repr=False)
    credential: InitialTargetCredential | None = Field(default=None, exclude=True, repr=False)

    @model_validator(mode="after")
    def valid_endpoint(self):
        if self.kind == "network":
            address = ipaddress.ip_address(self.address)
            if address.version != 4 or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                raise ValueError("Use an explicitly allowed unicast IPv4 target")
            self.port = self.port or 22
            if self.ssh_host_key and not re.fullmatch(r"(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+", self.ssh_host_key):
                raise ValueError("Supply the verified SSH public host key, not a password or private key")
            if self.url or self.web_ignore_https_errors or self.web_allowed_origins:
                raise ValueError("SSH targets cannot contain browser settings")
        else:
            parsed = urlsplit(self.url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or "\\" in self.url or any(ord(c) < 33 for c in self.url):
                raise ValueError("Web consoles require HTTP or HTTPS without embedded credentials or fragments")
            if len(parsed.hostname) > 120 or not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", parsed.hostname):
                raise ValueError("Web console hostname is too long")
            # URL is authoritative; ignore legacy address/port fields.
            self.address = parsed.hostname
            self.port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
            if not 1 <= self.port <= 65535:
                raise ValueError("Invalid web console port")
            self.ssh_host_key = ""
            allowed = []
            for value in self.web_allowed_origins:
                item = urlsplit(value.strip())
                if (item.scheme not in {"http", "https"} or not item.hostname or item.username is not None
                        or item.password is not None or item.path not in {"", "/"} or item.query or item.fragment
                        or "\\" in value or any(ord(c) < 33 for c in value) or len(item.hostname) > 120
                        or not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", item.hostname)):
                    raise ValueError("Redirect entries must be HTTP/HTTPS origins without paths, queries or credentials")
                port = item.port if item.port is not None else (443 if item.scheme == "https" else 80)
                if not 1 <= port <= 65535:
                    raise ValueError("Invalid redirect port")
                host = "[" + item.hostname + "]" if ":" in item.hostname else item.hostname
                normalized = f"{item.scheme}://{host}:{port}"
                if normalized not in allowed:
                    allowed.append(normalized)
            self.web_allowed_origins = sorted(allowed)
        return self
