from typing import Any

from ..db import Databases


class XdrRepository:
    def __init__(self, db: Databases):
        self.db = db

    def alerts(
        self,
        page: int,
        page_size: int,
        level: str | list[str] | None,
        status: str | None,
        categories: list[str] | None,
        start: float | None,
        end: float | None,
    ) -> tuple[int, bool, list[dict[str, Any]]]:
        filters: list[str] = []
        params: dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        if level:
            if isinstance(level, list):
                marks = ", ".join(f"{{lvl{i}:String}}" for i in range(len(level)))
                filters.append(f"level IN ({marks})")
                params.update({f"lvl{i}": value for i, value in enumerate(level)})
            else:
                filters.append("level = {level:String}")
                params["level"] = level
        if status:
            filters.append("status = {status:String}")
            params["status"] = status
        if categories:
            marks = ", ".join(f"{{cat{i}:String}}" for i in range(len(categories)))
            filters.append(f"category IN ({marks})")
            for i, value in enumerate(categories):
                params[f"cat{i}"] = value
        if start is not None:
            filters.append("event_time >= toDateTime({start:Float64})")
            params["start"] = start
        if end is not None:
            filters.append("event_time < toDateTime({end:Float64})")
            params["end"] = end
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        total = int(self.db.clickhouse.query(f"SELECT count() FROM xdr_alerts FINAL {where}", parameters=params).result_rows[0][0])
        rows = self.db.clickhouse.query(
            "SELECT uid AS id,event_time AS raisedAt,level,category,source_type AS sourceType,title,detail,suggestion,status,"
            "source_ip AS sourceIp,destination_ip AS destinationIp,entity_id AS entityId,relation_id AS relationId "
            f"FROM xdr_alerts FINAL {where} ORDER BY event_time DESC LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}",
            parameters=params,
        ).named_results()
        return total, (page * page_size) < total, list(rows)

    def alert_histogram(self, start: float, end: float, buckets: int, categories: list[str] | None) -> dict[str, Any]:
        bucket_seconds = (end - start) / buckets
        params: dict[str, Any] = {"start": start, "end": end, "bucket_seconds": bucket_seconds}
        cat_filter = ""
        if categories:
            marks = ", ".join(f"{{cat{i}:String}}" for i in range(len(categories)))
            cat_filter = f" AND category IN ({marks})"
            for i, value in enumerate(categories):
                params[f"cat{i}"] = value
        rows = self.db.clickhouse.query(
            "SELECT toUInt32((toUnixTimestamp(event_time) - {start:Float64}) / {bucket_seconds:Float64}) AS bucket, count() "
            "FROM xdr_alerts FINAL "
            "WHERE event_time >= toDateTime({start:Float64}) AND event_time < toDateTime({end:Float64})"
            f"{cat_filter} GROUP BY bucket",
            parameters=params,
        ).result_rows
        counts = [0] * buckets
        for bucket, count in rows:
            idx = max(0, min(buckets - 1, int(bucket)))
            counts[idx] = int(count)
        return {"start": start, "end": end, "bucketSeconds": bucket_seconds, "counts": counts}

    def flows(self, page: int, page_size: int, source_ip: str | None, destination_ip: str | None) -> tuple[int, list[dict[str, Any]]]:
        filters: list[str] = []
        params: dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        for key, value in (("source_ip", source_ip), ("destination_ip", destination_ip)):
            if value:
                filters.append(f"{key} = {{{key}:String}}")
                params[key] = value
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        total = int(self.db.clickhouse.query(f"SELECT count() FROM xdr_flows {where}", parameters=params).result_rows[0][0])
        rows = self.db.clickhouse.query(
            "SELECT uid AS id,event_time AS eventTime,source_ip AS sourceIp,source_port AS sourcePort,"
            "destination_ip AS destinationIp,destination_port AS destinationPort,up_bytes AS upBytes,"
            f"down_bytes AS downBytes,app_type AS appType,protocol FROM xdr_flows {where} "
            "ORDER BY event_time DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}", parameters=params
        ).named_results()
        return total, list(rows)

    def recent_events(self, lookback_seconds: int = 30) -> list[dict[str, Any]]:
        rows = self.db.clickhouse.query(
            "SELECT uid,event_time,level,category,source_type,source_ip,source_port,destination_ip,destination_port,protocol,title,detail,suggestion,status,entity_id,relation_id "
            "FROM xdr_alerts FINAL WHERE ingested_at > now64(3) - toIntervalSecond({lookback:UInt32}) "
            "ORDER BY ingested_at LIMIT 500",
            parameters={"lookback": lookback_seconds},
        ).named_results()
        return list(rows)

    def active_alerts(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.db.clickhouse.query(
            "SELECT uid,event_time,level,category,source_type,source_ip,source_port,destination_ip,destination_port,protocol,title,detail,suggestion,status,entity_id,relation_id "
            "FROM xdr_alerts FINAL WHERE status = 'active' ORDER BY event_time DESC LIMIT {limit:UInt32}",
            parameters={"limit": limit},
        ).named_results()
        return list(rows)

    def alert_summary(self) -> dict[str, Any]:
        row = self.db.clickhouse.query(
            "SELECT count(), countIf(status = 'active'), countIf(toDate(event_time) = today()), "
            "countIf(status = 'active' AND toDate(event_time) = today()) FROM xdr_alerts FINAL"
        ).result_rows[0]
        categories = {}
        for category, total, active, recent in self.db.clickhouse.query(
            "SELECT category,count(),countIf(status = 'active'),"
            "countIf(event_time >= now() - INTERVAL 10 MINUTE) FROM xdr_alerts FINAL GROUP BY category"
        ).result_rows:
            categories[str(category)] = {"total": int(total), "active": int(active), "recent": int(recent)}
        return {"total": int(row[0]), "active": int(row[1]), "today": int(row[2]), "todayActive": int(row[3]), "categories": categories}

    def entity_alert_summary(self, entity_id: str) -> dict[str, int]:
        row = self.db.clickhouse.query(
            "SELECT count() AS total, countIf(toDate(event_time) = today()) AS today "
            "FROM xdr_alerts FINAL WHERE entity_id = {entity_id:String}",
            parameters={"entity_id": entity_id},
        ).result_rows[0]
        return {"total": int(row[0]), "today": int(row[1])}

    def entity_alerts(self, entity_id: str, period: str, page: int, page_size: int) -> tuple[int, list[dict[str, Any]]]:
        today_filter = " AND toDate(event_time) = today()" if period == "today" else ""
        params = {"entity_id": entity_id, "limit": page_size, "offset": (page - 1) * page_size}
        total = int(self.db.clickhouse.query(
            f"SELECT count() FROM xdr_alerts FINAL WHERE entity_id = {{entity_id:String}}{today_filter}", parameters=params
        ).result_rows[0][0])
        rows = self.db.clickhouse.query(
            "SELECT uid AS id,event_time AS raisedAt,level,title,detail,suggestion,status,source_ip AS sourceIp,"
            "source_port AS sourcePort,destination_ip AS destinationIp,destination_port AS destinationPort,"
            "protocol,device_name AS deviceName,relation_id AS relationId "
            f"FROM xdr_alerts FINAL WHERE entity_id = {{entity_id:String}}{today_filter} "
            "ORDER BY event_time DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}", parameters=params
        ).named_results()
        return total, list(rows)
