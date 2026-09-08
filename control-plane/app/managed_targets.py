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
            if self.url:
                raise ValueError("SSH targets cannot contain browser settings")
        else:
            parsed = urlsplit(self.url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or any(ord(c) < 33 for c in self.url):
                raise ValueError("Web consoles require HTTPS without embedded credentials or fragments")
            if len(parsed.hostname) > 120:
                raise ValueError("Web console hostname is too long")
            # URL is authoritative; ignore legacy address/port fields.
            self.address, self.port = parsed.hostname, parsed.port or 443
            self.ssh_host_key = ""
        return self
