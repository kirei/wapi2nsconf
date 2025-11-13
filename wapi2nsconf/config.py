"""Configuration schema"""

import re
import ssl
from typing import Any, Self

import httpx
from pydantic import AnyHttpUrl, BaseModel, Field, FilePath, model_validator
from pydantic.networks import IPvAnyAddress


class WapiConfiguration(BaseModel):
    endpoint: AnyHttpUrl
    version: float | None = Field(default=None)
    username: str | None = Field(default=None)
    password: str | None = Field(default=None)
    ca_bundle: FilePath | None = Field(default=None)
    check_hostname: bool = Field(default=True)
    verify: bool = Field(default=True)
    timeout: int = Field(default=300)
    max_results: int = Field(default=1000, ge=1, le=100000)

    @model_validator(mode="after")
    def check_credentials(self) -> Self:
        if not self.username or not self.password:
            raise ValueError("Both username and password must be provided for basic auth.")
        return self

    def get_wapi_version(self) -> float | None:
        """Get WAPI configuration"""

        if self.version:
            return self.version
        endpoint = str(self.endpoint).rstrip("/")
        match = re.search(r"/wapi/v(\d+(?:\.\d+)?)$", endpoint)
        return float(match.group(1)) if match else None

    def get_httpx_client(self) -> httpx.Client:
        """Create HTTPX client from configuration"""

        kwargs: dict[str, Any] = {}

        if not self.verify:
            kwargs["verify"] = False
        else:
            ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.ca_bundle else ssl.create_default_context()
            ctx.check_hostname = self.check_hostname
            kwargs["verify"] = ctx

        if self.username and self.password:
            kwargs["auth"] = httpx.BasicAuth(username=self.username, password=self.password)

        kwargs["timeout"] = httpx.Timeout(timeout=self.timeout)

        return httpx.Client(**kwargs)


class IpamConfiguration(BaseModel):
    view: str = Field(default="default")
    views: list[str] | None = Field(default=None)
    ns_groups: list[str] | None = Field(default=None)
    extattr_key: str | None = Field(default=None)
    extattr_value: str | None = Field(default=None)

    @model_validator(mode="after")
    def check_extattr(self) -> Self:
        if not self.extattr_key and self.extattr_value:
            raise ValueError("extattr_key required when using extattr_value.")
        return self


class MasterConfiguration(BaseModel):
    ip: IPvAnyAddress
    tsig: str


class OutputConfiguration(BaseModel):
    template: str
    filename: str
    variables: dict[str, Any] = Field(default={})


class Configuration(BaseModel):
    wapi: WapiConfiguration
    ipam: IpamConfiguration
    masters: list[MasterConfiguration] = Field(default=[])
    output: list[OutputConfiguration] = Field(default=[])
