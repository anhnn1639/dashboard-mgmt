"""Validated connection metadata. No network access or credential forwarding."""
from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ManagedTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=100, pattern=r"^[\w .-]+$")
    kind: Literal["network", "web"]
    address: str = Field(max_length=45)
    port: int = Field(default=22, ge=1, le=65535)
    url: str = Field(default="", max_length=2048)
    ssh_host_key: str = Field(default="", max_length=2048)

    @model_validator(mode="after")
    def valid_endpoint(self):
        address = ipaddress.ip_address(self.address)
        if address.version != 4 or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError("Use an explicitly allowed unicast IPv4 target")
        if self.kind == "network":
            if self.ssh_host_key and not re.fullmatch(r"(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+", self.ssh_host_key):
                raise ValueError("Supply the verified SSH public host key, not a password or private key")
            if self.url:
                raise ValueError("SSH targets cannot contain browser settings")
        else:
            parsed = urlsplit(self.url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or any(ord(c) < 33 for c in self.url):
                raise ValueError("Web consoles require HTTPS without embedded credentials or fragments")
            if (parsed.port or 443) != self.port:
                raise ValueError("Port must match the HTTPS URL")
        return self


