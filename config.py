from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .nodes import clean_host


class PositiveWeights(BaseModel):
    @model_validator(mode="after")
    def positive(self):
        if not any(self.model_dump().values()):
            raise ValueError("至少配置一个大于零的权重")
        return self


class Weights(PositiveWeights):
    latency: float = Field(35, ge=0, le=100)
    speed: float = Field(25, ge=0, le=100)
    success: float = Field(30, ge=0, le=100)
    jitter: float = Field(10, ge=0, le=100)


class RecommendationWeights(PositiveWeights):
    stability: float = Field(35, ge=0, le=100)
    speed: float = Field(25, ge=0, le=100)
    latency: float = Field(25, ge=0, le=100)
    quality: float = Field(15, ge=0, le=100)


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connect_timeout: float = Field(3, ge=0.05, le=20)
    request_timeout: float = Field(5, ge=0.05, le=30)
    probe_timeout: float = Field(20, ge=0.1, le=90)
    retries: int = Field(1, ge=0, le=3)
    retry_delay: float = Field(0.3, ge=0, le=10)
    attempts: int = Field(2, ge=1, le=8)
    cdn_concurrency: int = Field(10, ge=1, le=50)
    turn_concurrency: int = Field(6, ge=1, le=20)
    max_candidates: int = Field(32, ge=1, le=256)
    cdn_domain: str = "speed.cloudflare.com"
    cdn_sni: str = ""
    cdn_host: str = ""
    cdn_scheme: Literal["http", "https"] = "https"
    cdn_port: int = Field(443, ge=1, le=65535)
    cdn_path: str = Field("/__down?bytes=262144", max_length=1500)
    download_bytes: int = Field(262144, ge=1, le=2_097_152)
    relay_mode: Literal["echo", "stun"] = "echo"
    relay_host: str = ""
    relay_port: int = Field(9000, ge=1, le=65535)
    relay_echo_timeout: float = Field(1.5, ge=0.05, le=15)
    weights: Weights = Field(default_factory=Weights)
    recommendation_weights: RecommendationWeights = Field(default_factory=RecommendationWeights)
    latency_target: float = Field(200, gt=0, le=5000)
    speed_target: float = Field(10, gt=0, le=1000)
    jitter_target: float = Field(40, gt=0, le=1000)
    change_ms: float = Field(20, ge=1, le=2000)
    change_score: float = Field(10, ge=1, le=100)
    top_n: int = Field(20, ge=1, le=500)
    update_policy: Literal["keep", "latest", "successful", "threshold", "top", "mark", "archive_stale"] = "top"
    min_recommend_score: float = Field(60, ge=0, le=100)
    stale_days: int = Field(30, ge=1, le=3650)
    quality_cache_hours: int = Field(24, ge=1, le=8760)
    quality_retention_days: int = Field(90, ge=1, le=3650)
    quality_interval_seconds: float = Field(1.5, ge=1, le=60)
    quality_ipapi_enabled: bool = False
    quality_ipwhois_enabled: bool = False
    quality_dbip_enabled: bool = True
    quality_location_fallback: bool = True
    quality_turn_type_fallback: bool = True
    auto_test_new: bool = False
    refresh_mode: Literal["append", "replace"] = "append"
    exit_url: str = Field("https://api64.ipify.org?format=json", max_length=1500)

    @field_validator("cdn_domain", "cdn_sni", "cdn_host", "relay_host")
    @classmethod
    def validate_dns_name(cls, value: str) -> str:
        return clean_host(value) if value else value

    @field_validator("cdn_domain")
    @classmethod
    def require_domain(cls, value: str) -> str:
        if not value:
            raise ValueError("检测域名不能为空")
        return value

    @field_validator("cdn_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//") or "#" in value or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError("请输入以 / 开头的请求路径，特殊字符需使用 URL 编码")
        return value

    @model_validator(mode="after")
    def validate_relay_host(self):
        if self.relay_host:
            try:
                ip = ip_address(self.relay_host)
            except ValueError:
                if self.relay_mode == "echo":
                    raise ValueError("UDP 原样回显需要填写 IP 地址") from None
            else:
                if ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                    raise ValueError("中继验证端点需要可路由的单播地址")
        return self
