"""画像数据访问：MySQL 快照/actor 表 + ClickHouse 告警聚合（docs/13 阶段1）。

- profile_snapshots：版本化画像快照，保留历史（docs/13 §5.5「当时判断/事后重评」）；
- security_actors：攻击者/用户终端实体持久化（不进 CMDB，独立表）；
- ClickHouse 聚合全部走 FINAL + 30d 窗口 + 参数化查询，口径见 services/profiling/levels.py。
"""

import json
from datetime import datetime, timezone
from typing import Any

from ..db import Databases

# 加权烈度 SQL 片段（与 levels.LEVEL_WEIGHTS 同口径，改动需同步两处并 bump 口径版本）
SEVERITY_WEIGHT_SQL = (
    "multiIf(level='4',10.0,level='3',10.0,level='2',4.0,level='1',1.0,level='0',0.1,0.0)"
)

# CVE 提取：兼容字符串与数组首元素（raw_json.cve）
CVE_EXTRACT_SQL = (
    "if(JSONExtractString(raw_json,'cve')!='',"
    "JSONExtractString(raw_json,'cve'),JSONExtractString(raw_json,'cve',1))"
)

# ATT&CK 提取：兼容 att_ck / attCk 两种键名
ATT_CK_EXTRACT_SQL = (
    "if(JSONExtractString(raw_json,'att_ck')!='',"
    "JSONExtractString(raw_json,'att_ck'),JSONExtractString(raw_json,'attCk'))"
)

# 攻击者地域观测（红线2：观测来源分布，非攻击者真实所在地）
ATTACKER_GEO_SQL = "JSONExtractString(raw_json,'attacker_host','geo_location')"

ATTACK_CATEGORY_SQL = "category IN ('attack-internal','attack-public')"


def _decode(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True, separators=(",", ":"))


class ProfilingRepository:
    def __init__(self, db: Databases):
        self.db = db

    # ------------------------------------------------------------ DDL

    def initialize(self) -> None:
        statements = [
            """CREATE TABLE IF NOT EXISTS profile_snapshots (
                entity_id VARCHAR(200) NOT NULL,
                version BIGINT NOT NULL,
                data_cutoff_at TIMESTAMP(6) NULL,
                topology_version BIGINT NULL,
                rule_version VARCHAR(64) NOT NULL,
                caliber_version VARCHAR(64) NOT NULL,
                payload JSON NOT NULL,
                created_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6),
                PRIMARY KEY(entity_id, version)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
            """CREATE TABLE IF NOT EXISTS security_actors (
                actor_id VARCHAR(32) PRIMARY KEY,
                kind VARCHAR(16) NOT NULL,
                ip VARCHAR(45) NOT NULL,
                status VARCHAR(16) NOT NULL,
                status_basis VARCHAR(500) NOT NULL DEFAULT '',
                evidence JSON NOT NULL,
                ttp JSON NOT NULL,
                cves JSON NOT NULL,
                geo_observations JSON NOT NULL,
                similar JSON NOT NULL,
                first_seen TIMESTAMP(6) NULL,
                last_seen TIMESTAMP(6) NULL,
                updated_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                UNIQUE KEY uq_kind_ip (kind, ip),
                INDEX idx_kind_status (kind, status)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
        ]
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            for statement in statements:
                cursor.execute(statement)
            cursor.close()

    # ------------------------------------------------------------ ClickHouse 聚合

    @staticmethod
    def _alert_aggregate_fields() -> str:
        return f"""
            count() AS total,
            countIf(toDate(event_time) = today()) AS today,
            countIf(status = 'active') AS active,
            countIf(category = 'violation') AS violation,
            countIf(category = 'blocked') AS blocked,
            countIf(category = 'attack-internal') AS attack_internal,
            countIf(category = 'attack-public') AS attack_public,
            countIf(category = 'system') AS system,
            countIf(title LIKE '%弱口令%') AS weak_password,
            countIf(event_time >= now() - INTERVAL 7 DAY) AS count7,
            countIf(event_time >= now() - INTERVAL 14 DAY AND event_time < now() - INTERVAL 7 DAY) AS count_prev7,
            sumIf({SEVERITY_WEIGHT_SQL}, event_time >= now() - INTERVAL 7 DAY) AS severity7,
            sumIf({SEVERITY_WEIGHT_SQL}, event_time >= now() - INTERVAL 30 DAY) AS severity30,
            toUnixTimestamp(max(event_time)) AS last_raised_at,
            uniqExact(concat(category, '|', title)) AS fingerprints,
            arrayFilter(x -> x != '', groupUniqArray(500)({CVE_EXTRACT_SQL})) AS cves,
            groupUniqArrayIf(500)(destination_ip, event_time >= now() - INTERVAL 1 DAY) AS recent_peers,
            groupUniqArrayIf(500)(destination_ip, event_time < now() - INTERVAL 1 DAY) AS baseline_peers,
            topK(5)(destination_ip) AS top_peers"""

    @staticmethod
    def _row_to_agg(row: dict[str, Any]) -> dict[str, Any]:
        """行 → indicators.compute_indicators 的 agg 入参。"""
        total = int(row["total"])
        count7 = int(row["count7"])
        return {
            "total": total,
            "today": int(row["today"]),
            "active": int(row["active"]),
            "by_category": {
                "violation": int(row["violation"]),
                "blocked": int(row["blocked"]),
                "attack-internal": int(row["attack_internal"]),
                "attack-public": int(row["attack_public"]),
                "system": int(row["system"]),
            },
            "weak_password": int(row["weak_password"]),
            "avg_severity7": (float(row["severity7"]) / count7) if count7 else None,
            "avg_severity30": (float(row["severity30"]) / total) if total else None,
            "cves": list(row["cves"]),
            "new_peers": [p for p in row["recent_peers"] if p not in set(row["baseline_peers"])],
            "top_peers": list(row["top_peers"]),
            "trend_cur7": count7,
            "trend_prev7": int(row["count_prev7"]),
            "recurrent_ratio": (total - int(row["fingerprints"])) / total if total else None,
            "last_raised_at": float(row["last_raised_at"]) if row["last_raised_at"] else None,
        }

    def entity_alert_aggregate(self, entity_id: str, hours: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        """单实体 30d 告警聚合；无告警时返回 None（调用方按「未知」处理）。"""
        row = self.db.clickhouse.query(
            f"SELECT {self._alert_aggregate_fields()} FROM xdr_alerts FINAL "
            "WHERE entity_id = {entity_id:String} AND event_time >= now() - INTERVAL 30 DAY",
            parameters={"entity_id": entity_id},
        ).named_results()
        row = list(row)
        if not row or not row[0]["total"]:
            return None
        agg = self._row_to_agg(row[0])
        if hours is not None:
            agg["hour_dist"] = {int(h): int(c) for h, c in hours}
        return agg

    def entity_hour_distribution(self, entity_id: str) -> list[tuple[int, int]]:
        rows = self.db.clickhouse.query(
            "SELECT toHour(event_time) AS h, count() AS c FROM xdr_alerts FINAL "
            "WHERE entity_id = {entity_id:String} AND event_time >= now() - INTERVAL 30 DAY GROUP BY h",
            parameters={"entity_id": entity_id},
        ).result_rows
        return [(int(h), int(c)) for h, c in rows]

    def alert_aggregates_by_entity(self, limit: int = 1000) -> dict[str, dict[str, Any]]:
        """批量聚合（worker 定时刷新用）：GROUP BY entity_id，entity_id='' 不参与（红线3）。"""
        rows = self.db.clickhouse.query(
            f"SELECT entity_id AS entity_id, {self._alert_aggregate_fields()} FROM xdr_alerts FINAL "
            "WHERE entity_id != '' AND event_time >= now() - INTERVAL 30 DAY "
            f"GROUP BY entity_id ORDER BY total DESC LIMIT {{limit:UInt32}}",
            parameters={"limit": limit},
        ).named_results()
        hour_rows = self.db.clickhouse.query(
            "SELECT entity_id AS entity_id, toHour(event_time) AS h, count() AS c FROM xdr_alerts FINAL "
            "WHERE entity_id != '' AND event_time >= now() - INTERVAL 30 DAY GROUP BY entity_id, h"
        ).result_rows
        hour_dist: dict[str, dict[int, int]] = {}
        for entity_id, h, c in hour_rows:
            hour_dist.setdefault(entity_id, {})[int(h)] = int(c)
        aggregates: dict[str, dict[str, Any]] = {}
        for row in rows:
            entity_id = row["entity_id"]
            aggregates[entity_id] = self._row_to_agg(row)
            aggregates[entity_id]["hour_dist"] = hour_dist.get(entity_id, {})
        return aggregates

    def ip_evidence(self, window_days: int = 30, limit: int = 5000) -> list[dict[str, Any]]:
        """按源 IP 聚合的 actor 证据（攻击者 + 用户终端共用，一条 SQL 单遍）。
        uid 去重由 ReplacingMergeTree FINAL 保证（红线6）。"""
        rows = self.db.clickhouse.query(
            f"""
            SELECT source_ip AS ip,
                countIf({ATTACK_CATEGORY_SQL}) AS attack_alerts,
                countIf(source_type = 'honeypot') AS honeypot_hits,
                uniqExact(concat(category, '|', title)) AS fingerprints,
                countIf(category = 'violation') AS violation,
                countIf(category = 'blocked') AS blocked,
                countIf(source_type = 'netctrl_violation') AS channel_marked,
                arrayFilter(x -> x != '', groupUniqArray(200)({CVE_EXTRACT_SQL})) AS cves,
                arrayFilter(x -> x != '', groupUniqArray(200)({ATT_CK_EXTRACT_SQL})) AS att_ck,
                arrayFilter(x -> x != '', groupUniqArray(200)({ATTACKER_GEO_SQL})) AS geo,
                toUnixTimestamp(min(event_time)) AS first_seen,
                toUnixTimestamp(max(event_time)) AS last_seen,
                count() AS total
            FROM xdr_alerts FINAL
            WHERE source_ip != '' AND event_time >= now() - toIntervalDay({{window_days:UInt32}})
            GROUP BY source_ip ORDER BY total DESC LIMIT {{limit:UInt32}}
            """,
            parameters={"window_days": window_days, "limit": limit},
        ).named_results()
        return [{
            "ip": row["ip"],
            "attack_alerts": int(row["attack_alerts"]),
            "honeypot_hits": int(row["honeypot_hits"]),
            "fingerprints": int(row["fingerprints"]),
            "violation": int(row["violation"]),
            "blocked": int(row["blocked"]),
            "channel_marked": int(row["channel_marked"]) > 0,
            "cves": list(row["cves"]),
            "att_ck": list(row["att_ck"]),
            "geo": list(row["geo"]),
            "first_seen": float(row["first_seen"]) if row["first_seen"] else None,
            "last_seen": float(row["last_seen"]) if row["last_seen"] else None,
        } for row in rows]

    def actor_alerts(self, ip: str, page: int, page_size: int) -> tuple[int, list[dict[str, Any]]]:
        """攻击者/用户终端 IP 关联的告警（源或目的）。"""
        params = {"ip": ip, "limit": page_size, "offset": (page - 1) * page_size}
        total = int(self.db.clickhouse.query(
            "SELECT count() FROM xdr_alerts FINAL "
            "WHERE (source_ip = {ip:String} OR destination_ip = {ip:String})",
            parameters={"ip": ip},
        ).result_rows[0][0])
        rows = self.db.clickhouse.query(
            "SELECT uid AS id,event_time AS raisedAt,level,category,source_type AS sourceType,title,detail,"
            "suggestion,status,source_ip AS sourceIp,source_port AS sourcePort,"
            "destination_ip AS destinationIp,destination_port AS destinationPort,"
            "protocol,device_name AS deviceName,entity_id AS entityId "
            "FROM xdr_alerts FINAL "
            "WHERE (source_ip = {ip:String} OR destination_ip = {ip:String}) "
            "ORDER BY event_time DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}",
            parameters=params,
        ).named_results()
        return total, list(rows)

    # ------------------------------------------------------------ MySQL 快照与 actor

    def asset_row(self, entity_id: str) -> dict[str, Any] | None:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT asset_id,name,kind,layer,zone,state,ip_address,attributes FROM assets WHERE asset_id=%s",
                           (entity_id,))
            row = cursor.fetchone()
            cursor.close()
        if row is None:
            return None
        row["attributes"] = _decode(row["attributes"] or {})
        return row

    def service_ports(self, entity_id: str) -> list[int]:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT port FROM services WHERE asset_id=%s AND status != 'stopped'", (entity_id,))
            ports = [int(row[0]) for row in cursor.fetchall()]
            cursor.close()
        return ports

    def asset_ips(self) -> set[str]:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM assets WHERE ip_address IS NOT NULL AND ip_address != ''")
            ips = {str(row[0]) for row in cursor.fetchall()}
            cursor.close()
        return ips


    def save_snapshot(self, entity_id: str, payload: dict[str, Any], meta: dict[str, Any]) -> None:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM profile_snapshots WHERE entity_id=%s",
                (entity_id,),
            )
            version = int(cursor.fetchone()[0])
            cursor.execute(
                "INSERT INTO profile_snapshots"
                "(entity_id,version,data_cutoff_at,topology_version,rule_version,caliber_version,payload) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (entity_id, version, meta.get("data_cutoff_at"), meta.get("topology_version"),
                 meta["rule_version"], meta["caliber_version"], _encode(payload)),
            )
            cursor.close()

    def latest_snapshot(self, entity_id: str) -> dict[str, Any] | None:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT payload,version,data_cutoff_at AS dataCutoffAt,topology_version AS topologyVersion,"
                "rule_version AS ruleVersion,caliber_version AS caliberVersion,created_at AS createdAt "
                "FROM profile_snapshots WHERE entity_id=%s ORDER BY version DESC LIMIT 1",
                (entity_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        if row is None:
            return None
        return {**{key: value for key, value in row.items() if key != "payload"},
                "payload": _decode(row["payload"])}

    def latest_snapshots(self) -> list[dict[str, Any]]:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT s.entity_id AS entityId,s.version,s.data_cutoff_at AS dataCutoffAt,"
                "s.topology_version AS topologyVersion,s.rule_version AS ruleVersion,"
                "s.caliber_version AS caliberVersion,s.payload,s.created_at AS createdAt "
                "FROM profile_snapshots s JOIN (SELECT entity_id,MAX(version) AS v FROM profile_snapshots GROUP BY entity_id) m "
                "ON s.entity_id=m.entity_id AND s.version=m.v ORDER BY s.entity_id",
            )
            rows = cursor.fetchall()
            cursor.close()
        return [{**{key: value for key, value in row.items() if key != "payload"},
                 "payload": _decode(row["payload"])} for row in rows]

    def delete_snapshots(self, entity_ids: list[str]) -> int:
        if not entity_ids:
            return 0
        marks = ", ".join(["%s"] * len(entity_ids))
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM profile_snapshots WHERE entity_id IN ({marks})", tuple(entity_ids))
            deleted = cursor.rowcount
            cursor.close()
        return deleted

    def upsert_actor(self, record: dict[str, Any]) -> None:
        def _epoch_to_dt(value: Any):
            # 聚合 SQL 产出 Unix 秒；TIMESTAMP 列只接受 datetime/ISO，这里统一转换
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
            return value

        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO security_actors"
                "(actor_id,kind,ip,status,status_basis,evidence,ttp,cves,geo_observations,similar,first_seen,last_seen) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE status=VALUES(status),status_basis=VALUES(status_basis),"
                "evidence=VALUES(evidence),ttp=VALUES(ttp),cves=VALUES(cves),"
                "geo_observations=VALUES(geo_observations),similar=VALUES(similar),"
                "first_seen=VALUES(first_seen),last_seen=VALUES(last_seen)",
                (record["actor_id"], record["kind"], record["ip"], record["status"],
                 record["status_basis"], _encode(record["evidence"]), _encode(record["ttp"]),
                 _encode(record["cves"]), _encode(record["geo_observations"]), _encode(record["similar"]),
                 _epoch_to_dt(record.get("first_seen")), _epoch_to_dt(record.get("last_seen"))),
            )
            cursor.close()

    def list_actors(self, kind: str | None, status: str | None, page: int, page_size: int,
                    ip: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        filters: list[str] = []
        params: list[Any] = []
        if kind:
            filters.append("kind=%s")
            params.append(kind)
        if status:
            filters.append("status=%s")
            params.append(status)
        if ip:
            filters.append("ip=%s")
            params.append(ip)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(f"SELECT COUNT(*) AS total FROM security_actors {where}", tuple(params))
            total = int(cursor.fetchone()["total"])
            cursor.execute(
                "SELECT actor_id AS actorId,kind,ip,status,status_basis AS statusBasis,evidence,ttp,cves,"
                "geo_observations AS geoObservations,similar,first_seen AS firstSeen,last_seen AS lastSeen,"
                f"updated_at AS updatedAt FROM security_actors {where} "
                "ORDER BY last_seen DESC LIMIT %s OFFSET %s",
                tuple(params + [page_size, (page - 1) * page_size]),
            )
            rows = cursor.fetchall()
            cursor.close()
        for row in rows:
            for key in ("evidence", "ttp", "cves", "geoObservations", "similar"):
                row[key] = _decode(row[key])
        return total, rows

    def get_actor(self, actor_id: str) -> dict[str, Any] | None:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT actor_id AS actorId,kind,ip,status,status_basis AS statusBasis,evidence,ttp,cves,"
                "geo_observations AS geoObservations,similar,first_seen AS firstSeen,last_seen AS lastSeen,"
                "updated_at AS updatedAt FROM security_actors WHERE actor_id=%s",
                (actor_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        if row is None:
            return None
        for key in ("evidence", "ttp", "cves", "geoObservations", "similar"):
            row[key] = _decode(row[key])
        return row

    def actor_by_ip(self, kind: str, ip: str) -> dict[str, Any] | None:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT actor_id AS actorId,kind,ip,status,status_basis AS statusBasis,evidence,ttp,cves,"
                "geo_observations AS geoObservations,similar,first_seen AS firstSeen,last_seen AS lastSeen,"
                "updated_at AS updatedAt FROM security_actors WHERE kind=%s AND ip=%s",
                (kind, ip),
            )
            row = cursor.fetchone()
            cursor.close()
        if row is None:
            return None
        for key in ("evidence", "ttp", "cves", "geoObservations", "similar"):
            row[key] = _decode(row[key])
        return row

    def delete_actors(self, actor_ids: list[str]) -> int:
        if not actor_ids:
            return 0
        marks = ", ".join(["%s"] * len(actor_ids))
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM security_actors WHERE actor_id IN ({marks})", tuple(actor_ids))
            deleted = cursor.rowcount
            cursor.close()
        return deleted
