import json
from typing import Any

import mysql.connector

from ..db import Databases

LEGACY_ALERT_CATEGORIES = {
    "entity": "system",
    "link": "blocked",
}

PUBLIC_ZONES = {"cn-public", "global-public", "attackers"}


def normalize_alert_categories(dataset: dict[str, Any]) -> dict[str, Any]:
    """Upgrade alert/notice categories in older stored topology snapshots.
    0910 内网/公网拆分：旧 'attack'/'security' 攻击标记按受害实体所在 zone 判定
    （快照自带 entities 即资产数据，zone 缺失时按内网兜底）。"""
    zones = {entity["id"]: entity.get("zone") for entity in dataset.get("entities", [])}
    for scenario in dataset.get("scenarios", []):
        for step in scenario.get("steps", []):
            for event in step.get("events", []):
                payload = event.get("alert") or event.get("notice")
                if not isinstance(payload, dict):
                    continue
                category = payload.get("category")
                if category in ("attack", "security"):
                    zone = zones.get(payload.get("entityId") or event.get("entityId"))
                    payload["category"] = "attack-public" if zone in PUBLIC_ZONES else "attack-internal"
                elif category in LEGACY_ALERT_CATEGORIES:
                    payload["category"] = LEGACY_ALERT_CATEGORIES[category]
    return dataset


class CmdbRepository:
    def __init__(self, db: Databases):
        self.db = db

    def dataset(self) -> dict[str, Any]:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT payload FROM topology_snapshots WHERE is_active=1 ORDER BY version DESC LIMIT 1")
            row = cursor.fetchone()
            cursor.close()
        if row is None:
            raise LookupError("CMDB has no active topology snapshot")
        payload = row["payload"]
        dataset = json.loads(payload) if isinstance(payload, str) else payload
        return normalize_alert_categories(dataset)

    def assets(self, page: int, page_size: int, query: str | None) -> tuple[int, list[dict[str, Any]]]:
        where = "WHERE (%s IS NULL OR asset_id LIKE CONCAT('%%',%s,'%%') OR name LIKE CONCAT('%%',%s,'%%'))"
        params: tuple[Any, ...] = (query, query, query)
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(f"SELECT COUNT(*) AS total FROM assets {where}", params)
            total = int(cursor.fetchone()["total"])
            # 0911 纳管维护：列表补 attributes，维护页编辑表单回填用
            cursor.execute(
                f"SELECT asset_id AS id,name,kind,layer,zone,state,ip_address AS ip,attributes,updated_at AS updatedAt "
                f"FROM assets {where} ORDER BY asset_id LIMIT %s OFFSET %s",
                params + (page_size, (page - 1) * page_size),
            )
            rows = cursor.fetchall()
            cursor.close()
            snapshot = self._active_snapshot_or_none(conn) if any(row["layer"] == "geo" for row in rows) else None
            geo_by_id = {e["id"]: e.get("geo") for e in snapshot[1].get("entities", [])} if snapshot else {}
        for row in rows:
            if row["layer"] == "geo":
                row["geo"] = geo_by_id.get(row["id"])
            if isinstance(row["attributes"], str):
                row["attributes"] = json.loads(row["attributes"])
        return total, rows

    def assistant_search(self, filters: dict) -> dict:
        """Parameterized exact predicates; LOCATE treats wildcard characters literally."""
        clauses, params = [], []
        for field, column in (("id", "asset_id"), ("name", "name"), ("ip", "ip_address"),
                              ("layer", "layer"), ("zone", "zone"), ("state", "state"), ("kind", "kind")):
            if filters[field]:
                clauses.append(f"{column} = %s")
                params.append(filters[field])
        q = filters["query"]
        if q:
            clauses.append("(LOCATE(LOWER(%s),LOWER(asset_id))>0 OR LOCATE(LOWER(%s),LOWER(name))>0 OR LOCATE(LOWER(%s),LOWER(ip_address))>0)")
            params.extend([q, q, q])
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(f"SELECT COUNT(*) AS total FROM assets {where}", tuple(params))
            total = int(cursor.fetchone()["total"])
            order = "asset_id"
            if q:
                order = "(LOWER(asset_id)=LOWER(%s) OR LOWER(name)=LOWER(%s) OR LOWER(ip_address)=LOWER(%s)) DESC,asset_id"
                params.extend([q, q, q])
            cursor.execute(f"SELECT asset_id AS id,name,ip_address AS ip,kind,layer,zone,state FROM assets {where} ORDER BY {order} LIMIT %s OFFSET %s",
                           tuple(params) + (filters["pageSize"], (filters["page"] - 1) * filters["pageSize"]))
            items = cursor.fetchall()
            cursor.close()
        return {"total": total, "items": items, "page": filters["page"], "pageSize": filters["pageSize"]}

    def assistant_overview(self) -> dict:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT layer,state,COUNT(*) AS count FROM assets GROUP BY layer,state ORDER BY layer,state")
            rows = cursor.fetchall()
            cursor.close()
        return {"total": sum(int(row["count"]) for row in rows), "byLayerAndState": rows}

    def assistant_services(self, asset_id: str) -> dict:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT COUNT(*) AS total FROM services WHERE asset_id=%s", (asset_id,))
            total = int(cursor.fetchone()["total"])
            # Do not send service configuration (which may contain credentials) to a model.
            cursor.execute("SELECT service_id AS id,name,protocol,port,status FROM services WHERE asset_id=%s ORDER BY service_id LIMIT 50", (asset_id,))
            rows = cursor.fetchall()
            cursor.close()
        return {"total": total, "items": rows}

    def services(self) -> list[dict[str, Any]]:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            # 0911 修正 2：补 config，CSV 导出与编辑表单回填用
            cursor.execute("SELECT service_id AS id,name,asset_id AS assetId,protocol,port,status,config,updated_at AS updatedAt FROM services ORDER BY service_id")
            rows = cursor.fetchall()
            cursor.close()
        for row in rows:
            if isinstance(row["config"], str):
                row["config"] = json.loads(row["config"])
        return rows

    def get_config(self, user_id: str) -> dict[str, Any] | None:
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT payload FROM user_configs WHERE user_id=%s", (user_id,))
            row = cursor.fetchone()
            cursor.close()
        if row is None:
            return None
        value = row["payload"]
        return json.loads(value) if isinstance(value, str) else value

    def save_config(self, user_id: str, payload: dict[str, Any]) -> None:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO user_configs(user_id,payload) VALUES(%s,%s) "
                "ON DUPLICATE KEY UPDATE payload=VALUES(payload),updated_at=CURRENT_TIMESTAMP",
                (user_id, json.dumps(payload, ensure_ascii=False)),
            )
            cursor.close()

    def delete_config(self, user_id: str) -> None:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_configs WHERE user_id=%s", (user_id,))
            cursor.close()

    def config_users(self) -> list[str]:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM user_configs ORDER BY user_id")
            users = [row[0] for row in cursor.fetchall()]
            cursor.close()
        return users

    # ---- CMDB 纳管维护：资产/服务 CRUD 与拓扑快照同步（0911）----

    @staticmethod
    def _active_snapshot_or_none(conn) -> tuple[int, dict[str, Any]] | None:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT version,payload FROM topology_snapshots WHERE is_active=1 ORDER BY version DESC LIMIT 1")
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            return None
        payload = row["payload"]
        return int(row["version"]), (json.loads(payload) if isinstance(payload, str) else payload)

    @staticmethod
    def _commit_snapshot(conn, version: int, payload: dict[str, Any]) -> None:
        """旧快照置非活动，新版本写入并置活动（3D 场景下次加载即读到新数据）。"""
        cursor = conn.cursor()
        cursor.execute("UPDATE topology_snapshots SET is_active=0 WHERE is_active=1")
        cursor.execute(
            "INSERT INTO topology_snapshots(version,payload,is_active) VALUES(%s,%s,1)",
            (version + 1, json.dumps(payload, ensure_ascii=False)),
        )
        cursor.close()

    def create_asset(self, row: dict[str, Any]) -> None:
        with self.db.mysql() as conn:
            snapshot = self._active_snapshot_or_none(conn)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO assets(asset_id,name,kind,layer,zone,state,ip_address,attributes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                    (row["id"], row["name"], row["kind"], row["layer"], row["zone"], row["state"], row["ip"],
                     json.dumps(row["attributes"], ensure_ascii=False)),
                )
            except mysql.connector.errors.IntegrityError as exc:
                if exc.errno == 1062:
                    raise ConflictError(f"资产 {row['id']} 已存在") from exc
                raise
            cursor.close()
            if snapshot is not None:
                version, payload = snapshot
                add_entity(payload, make_entity(payload, row))
                self._commit_snapshot(conn, version, payload)

    def update_asset(self, asset_id: str, patch: dict[str, Any]) -> None:
        column_map = {"name": "name", "state": "state", "zone": "zone", "ip": "ip_address",
                      "attributes": "attributes", "layer": "layer", "kind": "kind"}
        with self.db.mysql() as conn:
            # 资产行和活动快照一起提交；失败时不留下已迁层但场景未同步的资产。
            conn.start_transaction()
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT version,payload FROM topology_snapshots WHERE is_active=1 ORDER BY version DESC LIMIT 1 FOR UPDATE")
                snapshot = cursor.fetchone()
                payload = None
                if snapshot:
                    payload = snapshot["payload"]
                    if isinstance(payload, str):
                        payload = json.loads(payload)
                cursor.execute("SELECT layer,zone FROM assets WHERE asset_id=%s FOR UPDATE", (asset_id,))
                current = cursor.fetchone()
                if current is None:
                    raise NotFoundError(f"资产 {asset_id} 不存在")
                entity = next((e for e in (payload or {}).get("entities", []) if e["id"] == asset_id), None)
                effective = dict(patch)
                layer = effective.get("layer", current["layer"])
                if layer == "geo":
                    geo = (entity or {}).get("geo", {})
                    for key, axis in (("geoLat", "lat"), ("geoLng", "lng")):
                        if key not in effective and axis in geo:
                            effective[key] = geo[axis]
                        if key not in effective:
                            raise ValueError("地域层资产需填写 geoLat/geoLng 经纬度")
                    effective["zone"] = None
                else:
                    if "geoLat" in effective or "geoLng" in effective:
                        raise ValueError("仅地域层资产可设置经纬度")
                    if not effective.get("zone", current["zone"]):
                        raise ValueError("迁出地域层需选择目标区域 zone")
                # 有活动快照却缺少实体时，不允许只更新一端造成数据不一致。
                if payload is not None and entity is None:
                    raise ValueError("活动拓扑中缺少该资产，请先同步资产拓扑")
                keys = [key for key in effective if key in column_map]
                if keys:
                    fields = [f"{column_map[key]}=%s" for key in keys]
                    values = [json.dumps(effective[key], ensure_ascii=False) if key == "attributes" else effective[key] for key in keys]
                    cursor.execute(f"UPDATE assets SET {', '.join(fields)} WHERE asset_id=%s", values + [asset_id])
                if payload is not None and apply_asset_patch(payload, asset_id, effective):
                    self._commit_snapshot(conn, int(snapshot["version"]), payload)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def delete_asset(self, asset_id: str) -> None:
        with self.db.mysql() as conn:
            snapshot = self._active_snapshot_or_none(conn)
            cursor = conn.cursor()
            cursor.execute("SELECT service_id FROM services WHERE asset_id=%s", (asset_id,))
            services = [row[0] for row in cursor.fetchall()]
            if services:
                preview = ", ".join(services[:3]) + ("…" if len(services) > 3 else "")
                raise ConflictError(f"资产 {asset_id} 下存在 {len(services)} 个服务（{preview}），请先删除相关服务")
            if snapshot is not None:
                version, payload = snapshot
                children = snapshot_children(payload, asset_id)
                if children:
                    preview = ", ".join(children[:3]) + ("…" if len(children) > 3 else "")
                    raise ConflictError(f"拓扑快照中存在 {len(children)} 个子实体（{preview}），请先删除子实体")
            cursor.execute("DELETE FROM assets WHERE asset_id=%s", (asset_id,))
            deleted = cursor.rowcount
            cursor.close()
            if deleted == 0:
                raise NotFoundError(f"资产 {asset_id} 不存在")
            if snapshot is not None:
                remove_entity(payload, asset_id)
                self._commit_snapshot(conn, version, payload)

    def create_service(self, row: dict[str, Any]) -> None:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM assets WHERE asset_id=%s", (row["assetId"],))
            if cursor.fetchone() is None:
                cursor.close()
                raise NotFoundError(f"所属资产 {row['assetId']} 不存在")
            try:
                cursor.execute(
                    "INSERT INTO services(service_id,name,asset_id,protocol,port,status,config) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (row["id"], row["name"], row["assetId"], row["protocol"], row["port"], row["status"],
                     json.dumps(row["config"], ensure_ascii=False)),
                )
            except mysql.connector.errors.IntegrityError as exc:
                if exc.errno == 1062:
                    raise ConflictError(f"服务 {row['id']} 已存在") from exc
                raise
            cursor.close()

    def update_service(self, service_id: str, patch: dict[str, Any]) -> None:
        column_map = {"name": "name", "assetId": "asset_id", "protocol": "protocol", "port": "port", "status": "status", "config": "config"}
        fields = [f"{column_map[key]}=%s" for key in patch]
        values: list[Any] = [
            json.dumps(patch["config"], ensure_ascii=False) if key == "config" else patch[key] for key in patch
        ]
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            if "assetId" in patch:
                cursor.execute("SELECT 1 FROM assets WHERE asset_id=%s", (patch["assetId"],))
                if cursor.fetchone() is None:
                    cursor.close()
                    raise NotFoundError(f"所属资产 {patch['assetId']} 不存在")
            try:
                cursor.execute(f"UPDATE services SET {', '.join(fields)} WHERE service_id=%s", values + [service_id])
            except mysql.connector.errors.IntegrityError as exc:
                # 外键 1452 兜底（assetId 并发删除等）
                if exc.errno == 1452:
                    raise NotFoundError(f"所属资产 {patch.get('assetId')} 不存在") from exc
                raise
            updated = cursor.rowcount
            cursor.close()
            if updated == 0:
                raise NotFoundError(f"服务 {service_id} 不存在")

    def delete_service(self, service_id: str) -> None:
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM services WHERE service_id=%s", (service_id,))
            deleted = cursor.rowcount
            cursor.close()
            if deleted == 0:
                raise NotFoundError(f"服务 {service_id} 不存在")

    # ---- CMDB 纳管维护：批量导入/批量删除（0911 修正 2/3）----

    def import_assets(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """批量新建资产：ID 已存在则跳过不覆盖；创建成功的实体一次性并入活动快照。"""
        created: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            for row in rows:
                try:
                    cursor.execute(
                        "INSERT INTO assets(asset_id,name,kind,layer,zone,state,ip_address,attributes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                        (row["id"], row["name"], row["kind"], row["layer"], row["zone"], row["state"], row["ip"],
                         json.dumps(row["attributes"], ensure_ascii=False)),
                    )
                    created.append(row)
                except mysql.connector.errors.IntegrityError as exc:
                    if exc.errno == 1062:
                        skipped.append({"id": row["id"], "reason": "已存在"})
                        continue
                    raise
            cursor.close()
            if created:
                snapshot = self._active_snapshot_or_none(conn)
                if snapshot is not None:
                    version, payload = snapshot
                    for row in created:
                        add_entity(payload, make_entity(payload, row))
                    self._commit_snapshot(conn, version, payload)
        return {"created": len(created), "skipped": skipped}

    def import_services(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """批量新建服务：所属资产不存在或 ID 重复均跳过，其余写入 services 表。"""
        created = 0
        skipped: list[dict[str, str]] = []
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            for row in rows:
                cursor.execute("SELECT 1 FROM assets WHERE asset_id=%s", (row["assetId"],))
                if cursor.fetchone() is None:
                    skipped.append({"id": row["id"], "reason": f"所属资产 {row['assetId']} 不存在"})
                    continue
                try:
                    cursor.execute(
                        "INSERT INTO services(service_id,name,asset_id,protocol,port,status,config) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                        (row["id"], row["name"], row["assetId"], row["protocol"], row["port"], row["status"],
                         json.dumps(row["config"], ensure_ascii=False)),
                    )
                    created += 1
                except mysql.connector.errors.IntegrityError as exc:
                    if exc.errno == 1062:
                        skipped.append({"id": row["id"], "reason": "已存在"})
                        continue
                    raise
            cursor.close()
        return {"created": created, "skipped": skipped}

    def batch_delete_assets(self, asset_ids: list[str]) -> dict[str, Any]:
        """批量删除资产：逐条独立尝试（外键/子实体冲突或不存在记入 failed）；
        子实体先于父实体删除，全部成功后一次性提交活动快照。"""
        deleted: list[str] = []
        failed: list[dict[str, str]] = []
        with self.db.mysql() as conn:
            snapshot = self._active_snapshot_or_none(conn)
            version, payload = snapshot if snapshot is not None else (None, None)
            pending = list(asset_ids)
            while pending:
                progressed = False
                deferred: list[str] = []
                for asset_id in pending:
                    cursor = conn.cursor()
                    cursor.execute("SELECT service_id FROM services WHERE asset_id=%s", (asset_id,))
                    services = [row[0] for row in cursor.fetchall()]
                    if services:
                        preview = ", ".join(services[:3]) + ("…" if len(services) > 3 else "")
                        failed.append({"id": asset_id, "reason": f"存在 {len(services)} 个服务（{preview}）"})
                        cursor.close()
                        progressed = True
                        continue
                    if payload is not None and snapshot_children(payload, asset_id):
                        deferred.append(asset_id)
                        cursor.close()
                        continue
                    cursor.execute("DELETE FROM assets WHERE asset_id=%s", (asset_id,))
                    removed = cursor.rowcount
                    cursor.close()
                    if removed == 0:
                        failed.append({"id": asset_id, "reason": "不存在"})
                        progressed = True
                        continue
                    deleted.append(asset_id)
                    if payload is not None:
                        remove_entity(payload, asset_id)
                    progressed = True
                if not progressed:
                    for asset_id in deferred:
                        failed.append({"id": asset_id, "reason": "存在子实体，请先删除子实体"})
                    break
                pending = deferred
            if deleted and payload is not None:
                self._commit_snapshot(conn, version, payload)
        return {"deleted": len(deleted), "failed": failed}

    def batch_delete_services(self, service_ids: list[str]) -> dict[str, Any]:
        """批量删除服务：仅写 services 表，逐条独立尝试。"""
        deleted = 0
        failed: list[dict[str, str]] = []
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            for service_id in service_ids:
                cursor.execute("DELETE FROM services WHERE service_id=%s", (service_id,))
                if cursor.rowcount == 0:
                    failed.append({"id": service_id, "reason": "不存在"})
                    continue
                deleted += 1
            cursor.close()
        return {"deleted": deleted, "failed": failed}


class NotFoundError(Exception):
    """CMDB CRUD 目标记录不存在。"""


class ConflictError(Exception):
    """存在依赖（服务外键 / 快照子实体 / 主键重复）阻止操作。"""


def _sync_meta(payload: dict[str, Any]) -> None:
    meta = payload.get("meta")
    if isinstance(meta, dict):
        meta["entityCount"] = len(payload.get("entities", []))
        meta["relationCount"] = len(payload.get("relations", []))


def apply_asset_patch(payload: dict[str, Any], asset_id: str, patch: dict[str, Any]) -> bool:
    """把资产字段修改合并进快照 payload（name/state/zone/ip/attributes→attrs）。

    返回是否有实际变更。快照实体字段比 MySQL 行更丰富（config/ops/stats/geo 等），
    仅覆盖共享字段；attributes 为整体替换语义（缺键即删除，与 MySQL attributes 列一致）。"""
    entity = next((e for e in payload.get("entities", []) if e["id"] == asset_id), None)
    if entity is None:
        return False
    changed = False
    old_layer = entity.get("layer")
    old_zone = entity.get("zone")
    if "kind" in patch and entity.get("kind") != patch["kind"]:
        entity["kind"] = patch["kind"]
        entity["kindLabel"] = model_kind_label(payload, patch["kind"], asset_id)
        changed = True
    if "layer" in patch and old_layer != patch["layer"]:
        entity["layer"] = patch["layer"]
        changed = True
    if entity.get("layer") == "geo":
        if "zone" in entity:
            del entity["zone"]
            changed = True
        geo = dict(entity.get("geo", {}))
        for key, axis in (("geoLat", "lat"), ("geoLng", "lng")):
            if key in patch:
                geo[axis] = patch[key]
        if geo and entity.get("geo") != geo:
            entity["geo"] = geo
            changed = True
    elif "geo" in entity:
        del entity["geo"]
        changed = True
    if "name" in patch and entity.get("name") != patch["name"]:
        entity["name"] = patch["name"]
        changed = True
    if "state" in patch and entity.get("state") != patch["state"]:
        entity["state"] = patch["state"]
        changed = True
    if "zone" in patch and patch["zone"] is not None and entity.get("layer") != "geo" and entity.get("zone") != patch["zone"]:
        entity["zone"] = patch["zone"]
        changed = True
    if old_layer != entity.get("layer") or old_zone != entity.get("zone"):
        entities = {e["id"]: e for e in payload.get("entities", [])}
        # 树形布局只接受同层同区域父节点；解除已不适用的布局归属，保留业务连线。
        for child in entities.values():
            if child["id"] != asset_id and child.get("parentId") != asset_id:
                continue
            parent = entities.get(child.get("parentId"))
            if parent and (parent.get("layer"), parent.get("zone")) != (child.get("layer"), child.get("zone")):
                child.pop("parentId", None)
        for relation in payload.get("relations", []):
            if asset_id not in (relation.get("from"), relation.get("to")):
                continue
            source, target = entities.get(relation.get("from")), entities.get(relation.get("to"))
            if not source or not target:
                continue
            cross = source["layer"] != target["layer"]
            relation["scope"] = "cross" if cross else "intra"
            if cross:
                pair = frozenset((source["layer"], target["layer"]))
                relation["crossType"] = {
                    frozenset(("geo", "device")): "deploy",
                    frozenset(("device", "app")): "run",
                    frozenset(("app", "task")): "bear",
                }.get(pair, "own")
            else:
                relation.pop("crossType", None)
    if "attributes" in patch:
        wanted = patch["attributes"]
        attrs = entity.setdefault("attrs", [])
        kept = [a for a in attrs if a.get("key") in wanted]
        if len(kept) != len(attrs):
            changed = True
        by_key = {a.get("key"): a for a in kept}
        for key, value in wanted.items():
            if key in by_key:
                if by_key[key].get("value") != value:
                    by_key[key]["value"] = value
                    changed = True
            else:
                kept.append({"key": key, "label": key, "value": value})
                changed = True
        entity["attrs"] = kept
    if "ip" in patch and patch["ip"] is not None:
        attrs = entity.setdefault("attrs", [])
        ip_attr = next((a for a in attrs if "ip" in str(a.get("key", "")).lower()), None)
        if ip_attr is None:
            attrs.append({"key": "ip", "label": "IP 地址", "value": patch["ip"]})
            changed = True
        elif ip_attr.get("value") != patch["ip"]:
            ip_attr["value"] = patch["ip"]
            changed = True
    return changed


def snapshot_children(payload: dict[str, Any], entity_id: str) -> list[str]:
    """快照中以 entity_id 为 parentId 的子实体（删除前置检查）。"""
    return [e["id"] for e in payload.get("entities", []) if e.get("parentId") == entity_id]


def remove_entity(payload: dict[str, Any], entity_id: str) -> list[str]:
    """从快照删除实体：连带删除触碰的关系，并清理剧本中引用这些实体的动态事件。

    返回被删除的关系 id 列表（调用方可据此提示影响范围）。"""
    payload["entities"] = [e for e in payload.get("entities", []) if e["id"] != entity_id]
    removed_rels = [r["id"] for r in payload.get("relations", []) if r.get("from") == entity_id or r.get("to") == entity_id]
    removed_set = {entity_id, *removed_rels}
    if removed_rels:
        payload["relations"] = [r for r in payload.get("relations", []) if r["id"] not in removed_set]
    for scenario in payload.get("scenarios", []):
        for step in scenario.get("steps", []):
            kept = []
            for ev in step.get("events", []):
                refs: list[Any] = []
                if ev.get("type") in ("entity:state", "stat:update"):
                    refs = [ev.get("entityId")]
                elif ev.get("type") == "alert:raise":
                    alert = ev.get("alert") or {}
                    refs = [alert.get("entityId"), alert.get("relationId")]
                elif ev.get("type") in ("relation:volume", "relation:kind"):
                    refs = [ev.get("relationId")]
                if any(ref in removed_set for ref in refs if ref):
                    continue
                kept.append(ev)
            step["events"] = kept
    _sync_meta(payload)
    return removed_rels


def add_entity(payload: dict[str, Any], entity: dict[str, Any]) -> None:
    """新增实体追加到快照末尾（校验要求 parentId 引用先于自身的实体，追加即安全）。"""
    payload.setdefault("entities", []).append(entity)
    _sync_meta(payload)


def model_kind_label(payload: dict[str, Any], kind: str, exclude_id: str | None = None) -> str:
    if kind == "cell-phone":
        return "手机设备"
    return next((e.get("kindLabel", kind) for e in payload.get("entities", [])
                 if e.get("kind") == kind and (exclude_id is None or e.get("id") != exclude_id)), kind)


def make_entity(payload: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """按快照实体形状构造新实体（层/类型/名称 + 属性平铺为 attrs）。

    geo 层用 row 的 geoLat/geoLng；非 geo 层用 zone（无经纬度，场景按区域布位）。"""
    kind_label = model_kind_label(payload, row["kind"])
    entity: dict[str, Any] = {
        "id": row["id"],
        "layer": row["layer"],
        "kind": row["kind"],
        "kindLabel": kind_label,
        "name": row["name"],
        "size": 1,
        "state": row["state"],
        "attrs": [{"key": key, "label": key, "value": value} for key, value in (row["attributes"] or {}).items()],
        "config": [],
        "ops": [],
        "stats": [],
    }
    if row["layer"] == "geo":
        entity["geo"] = {"lat": row["geoLat"], "lng": row["geoLng"]}
    else:
        entity["zone"] = row["zone"]
    return entity
