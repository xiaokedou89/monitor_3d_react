from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(Path(__file__).resolve().parents[1] / ".env", Path(__file__).resolve().parents[2] / ".dev"), extra="ignore")

    assistant_enabled: bool = True
    llm_base_url: str = "https://api.siliconflow.cn/v1"
    llm_api_key: SecretStr = SecretStr("")
    llm_model: str = "deepseek-ai/DeepSeek-V4-Flash"
    llm_timeout_seconds: float = Field(60, ge=1, le=120)
    llm_max_tokens: int = Field(4096, ge=256, le=16384)
    assistant_timeout_seconds: float = Field(180, ge=5, le=300)
    report_llm_read_timeout_seconds: float = Field(120, ge=1, le=600)
    report_analysis_timeout_seconds: float = Field(300, ge=5, le=900)
    report_llm_max_tokens: int = Field(8192, ge=256, le=32768)
    assistant_config: str = "config/assistant.toml"

    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 9528
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    cors_origin_regex: str | None = r"^http://(localhost|127\.0\.0\.1):\d+$"
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 13306
    mysql_database: str = "globalctl_cmdb"
    mysql_user: str = "globalctl"
    mysql_password: str = "globalctl_dev_password"
    clickhouse_host: str = "127.0.0.1"
    clickhouse_http_port: int = 18123
    clickhouse_database: str = "globalctl_xdr"
    clickhouse_user: str = "globalctl"
    clickhouse_password: str = "globalctl_dev_password"
    xdr_base_url: str = "https://10.231.7.78:8072/api/v1/logweb/threatanalysis-logretrieval"
    xdr_token: str = ""
    xdr_verify_tls: bool = False
    xdr_poll_seconds: int = 10
    xdr_lookback_seconds: int = 300
    sse_poll_seconds: float = 2.0

    # 多层次实体安全画像（docs/13 阶段1；PROFILE_* 环境变量可覆盖）
    profile_enabled: bool = True
    profile_cache_ttl_seconds: int = Field(120, ge=10, le=3600)
    profile_refresh_interval_seconds: int = Field(300, ge=60, le=86400)
    profile_actor_interval_seconds: int = Field(300, ge=60, le=86400)
    profile_actor_min_evidence: int = Field(2, ge=1, le=100)
    profile_actor_max_evidence: int = Field(50, ge=1, le=500)
    profile_actor_window_days: int = Field(30, ge=1, le=180)
    profile_actor_initial_lookback_hours: int = Field(72, ge=1, le=720)
    profile_actor_entities_cap: int = Field(200, ge=1, le=2000)
    profile_user_terminal_cidrs: str = "100.64.0.0/10"
    profile_work_hours: str = "8-19"
    profile_severity_thresholds: str = "8,4"

    @property
    def cors_origin_list(self) -> list[str]:
        return [part.strip() for part in self.cors_origins.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
