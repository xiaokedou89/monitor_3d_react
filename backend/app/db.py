from contextlib import contextmanager
from typing import Iterator

import clickhouse_connect
import mysql.connector
from clickhouse_connect.driver.client import Client
from mysql.connector.pooling import MySQLConnectionPool, PooledMySQLConnection

from .config import Settings


class Databases:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.mysql_pool: MySQLConnectionPool | None = None
        self._clickhouse: Client | None = None

    def connect(self) -> None:
        self.mysql_pool = MySQLConnectionPool(
            pool_name="globalctl",
            pool_size=8,
            host=self.settings.mysql_host,
            port=self.settings.mysql_port,
            database=self.settings.mysql_database,
            user=self.settings.mysql_user,
            password=self.settings.mysql_password,
            autocommit=True,
        )
        self._clickhouse = clickhouse_connect.get_client(
            host=self.settings.clickhouse_host,
            port=self.settings.clickhouse_http_port,
            database=self.settings.clickhouse_database,
            username=self.settings.clickhouse_user,
            password=self.settings.clickhouse_password,
            # FastAPI serves REST queries and long-running SSE polling in
            # parallel. Stateless queries must not share a ClickHouse session.
            autogenerate_session_id=False,
        )
        self.check_mysql()
        self.check_clickhouse()
        self.clickhouse.command("ALTER TABLE xdr_alerts ADD COLUMN IF NOT EXISTS category LowCardinality(String) DEFAULT 'attack' AFTER level")
        self.clickhouse.command("ALTER TABLE xdr_alerts ADD COLUMN IF NOT EXISTS source_type LowCardinality(String) DEFAULT 'safe' AFTER category")
        # 0910 内网/公网拆分迁移（幂等：WHERE 限定类别集合）：
        # 旧 'attack' 行按 raw_json 中 victim_host.safety_tag 改写为 attack-internal/attack-public；
        # ReplacingMergeTree+TTL180d 下历史行可读，读取路径仍容忍残留 'attack' 值（前端 foldLegacyCategory）。
        self.clickhouse.command(
            "ALTER TABLE xdr_alerts UPDATE category = multiIf("
            "JSONExtractString(raw_json, 'victim_host', 'safety_tag') = '外网', 'attack-public', "
            "'attack-internal') WHERE category IN ('attack', 'attack-internal', 'attack-public')"
        )

    @contextmanager
    def mysql(self) -> Iterator[PooledMySQLConnection]:
        if self.mysql_pool is None:
            raise RuntimeError("MySQL pool is not initialized")
        conn = self.mysql_pool.get_connection()
        try:
            yield conn
        finally:
            conn.close()

    @property
    def clickhouse(self) -> Client:
        if self._clickhouse is None:
            raise RuntimeError("ClickHouse client is not initialized")
        return self._clickhouse

    def check_mysql(self) -> None:
        with self.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()

    def check_clickhouse(self) -> None:
        self.clickhouse.command("SELECT 1")
