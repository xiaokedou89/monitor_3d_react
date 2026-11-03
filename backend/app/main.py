import asyncio
import json
import re
from contextlib import asynccontextmanager, suppress
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .config import get_settings
from .db import Databases
from .repositories.cmdb import CmdbRepository, ConflictError, NotFoundError
from .repositories.xdr import XdrRepository
from .services.events import alert_event
from .services.assistant import router as assistant_router
from .services.assistant_history import router as assistant_history_router
from .repositories.assistant_history import AssistantHistoryRepository

from .repositories.operations import OperationsRepository
from .services.operations import router as operations_router, report_worker
from .services.message_browser import router as message_browser_router
from .services.message_trends import router as message_trends_router
from .repositories.profiling import ProfilingRepository
from .services.profiling.router import router as profiling_router
from .services.profiling.service import ProfilingService
from .services.profiling.worker import profiling_worker
from .services.profiling.levels import ACTOR_ID_PREFIX

settings = get_settings()
db = Databases(settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await asyncio.to_thread(db.connect)
    app.state.cmdb = CmdbRepository(db)
    app.state.xdr = XdrRepository(db)
    app.state.assistant_history = AssistantHistoryRepository(db)
    await asyncio.to_thread(app.state.assistant_history.initialize)
    app.state.operations = OperationsRepository(db)
    await asyncio.to_thread(app.state.operations.initialize)
    app.state.profiling_repo = ProfilingRepository(db)
    await asyncio.to_thread(app.state.profiling_repo.initialize)
    app.state.profiling = ProfilingService(settings, db, app.state.cmdb, app.state.profiling_repo) if settings.profile_enabled else None
    worker = asyncio.create_task(report_worker(app.state.operations))
    profile_task = (
        asyncio.create_task(profiling_worker(app.state.profiling, settings))
        if settings.profile_enabled else None
    )
    try:
        yield
    finally:
        worker.cancel()
        with suppress(asyncio.CancelledError):
            await worker
        if profile_task is not None:
            profile_task.cancel()
            with suppress(asyncio.CancelledError):
                await profile_task


app = FastAPI(title="Global Monitor API", version="1.0.0", lifespan=lifespan)
app.include_router(operations_router)
app.include_router(message_browser_router)
app.include_router(message_trends_router)
app.include_router(assistant_router)
app.include_router(assistant_history_router)
app.include_router(profiling_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Last-Event-ID"],
)


def response(data: object = None, message: str = "success") -> dict[str, object]:
    return {"code": 0, "message": message, "data": data}


@app.get("/healthz")
async def healthz() -> dict[str, object]:
    return {"ok": True, "service": "global-monitor-api", "version": app.version}


@app.get("/readyz")
async def readyz() -> dict[str, object]:
    checks: dict[str, str] = {}
    for name, check in (("mysql", db.check_mysql), ("clickhouse", db.check_clickhouse)):
        try:
            await asyncio.to_thread(check)
            checks[name] = "up"
        except Exception as exc:
            checks[name] = f"down: {type(exc).__name__}"
    if any(value != "up" for value in checks.values()):
        raise HTTPException(503, detail=checks)
    return {"ok": True, "dependencies": checks}


@app.get("/api/v1/dataset")
async def dataset(request: Request):
    payload = await asyncio.to_thread(request.app.state.cmdb.dataset)
    if request.app.state.profiling is not None:
        # 富化：追加 actor 实体（攻击者/用户终端，不改动 CMDB 快照本身）
        payload = await asyncio.to_thread(request.app.state.profiling.merged_dataset, payload)
    return payload


@app.get("/api/v1/assets")
async def assets(request: Request, page: int = Query(1, ge=1), page_size: int = Query(50, alias="pageSize", ge=1, le=500), q: str | None = None):
    total, items = await asyncio.to_thread(request.app.state.cmdb.assets, page, page_size, q)
    return response({"total": total, "page": page, "pageSize": page_size, "items": items})


@app.get("/api/v1/services")
async def services(request: Request):
    return response({"items": await asyncio.to_thread(request.app.state.cmdb.services)})


ALERT_CATEGORY_PATTERN = "^(attack|violation|blocked|attack-internal|attack-public|system)$"


def validate_categories(categories: list[str] | None) -> list[str] | None:
    """可重复 category 参数逐项校验（Query(pattern=) 对 list 参数不逐项生效）。"""
    if not categories:
        return categories
    for value in categories:
        if re.fullmatch(ALERT_CATEGORY_PATTERN, value) is None:
            raise HTTPException(422, f"invalid category value: {value}")
    return categories


@app.get("/api/v1/alerts")
async def alerts(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=500),
    level: str | None = None,
    status: str | None = None,
    category: list[str] | None = Query(None),
    start: float | None = Query(None, description="起始时间（epoch 秒，含端）"),
    end: float | None = Query(None, description="结束时间（epoch 秒，开区间）"),
):
    category = validate_categories(category)
    total, has_more, items = await asyncio.to_thread(request.app.state.xdr.alerts, page, page_size, level, status, category, start, end)
    return response({"total": total, "page": page, "pageSize": page_size, "hasMore": has_more, "items": items})


@app.get("/api/v1/alerts/histogram")
async def alert_histogram(
    request: Request,
    start: float = Query(..., description="起始时间（epoch 秒）"),
    end: float = Query(..., description="结束时间（epoch 秒）"),
    buckets: int = Query(360, ge=1, le=1000),
    category: list[str] | None = Query(None),
):
    if end <= start:
        raise HTTPException(400, "end must be greater than start")
    category = validate_categories(category)
    return response(await asyncio.to_thread(request.app.state.xdr.alert_histogram, start, end, buckets, category))


@app.get("/api/v1/alerts/summary")
async def alert_summary(request: Request):
    return response(await asyncio.to_thread(request.app.state.xdr.alert_summary))


@app.get("/api/v1/flows")
async def flows(request: Request, page: int = Query(1, ge=1), page_size: int = Query(50, alias="pageSize", ge=1, le=500), source_ip: str | None = None, destination_ip: str | None = None):
    total, items = await asyncio.to_thread(request.app.state.xdr.flows, page, page_size, source_ip, destination_ip)
    return response({"total": total, "page": page, "pageSize": page_size, "items": items})


@app.get("/api/v1/entities/{entity_id}/alerts/summary")
async def entity_alert_summary(entity_id: str, request: Request):
    if entity_id.startswith(ACTOR_ID_PREFIX):
        if request.app.state.profiling is None:
            raise HTTPException(503, "profiling is disabled")
        try:
            total, _ = await asyncio.to_thread(request.app.state.profiling.actor_alerts, entity_id, 1, 1)
        except KeyError as exc:
            raise HTTPException(404, "actor not found") from exc
        return response({"total": total, "today": 0})
    return response(await asyncio.to_thread(request.app.state.xdr.entity_alert_summary, entity_id))


@app.get("/api/v1/entities/{entity_id}/alerts")
async def entity_alerts(
    entity_id: str,
    request: Request,
    period: str = Query("all", pattern="^(all|today)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, alias="pageSize", ge=1, le=500),
):
    if entity_id.startswith(ACTOR_ID_PREFIX):
        if request.app.state.profiling is None:
            raise HTTPException(503, "profiling is disabled")
        try:
            total, items = await asyncio.to_thread(
                request.app.state.profiling.actor_alerts, entity_id, page, page_size)
        except KeyError as exc:
            raise HTTPException(404, "actor not found") from exc
        return response({"total": total, "page": page, "pageSize": page_size, "period": period, "items": items})
    total, items = await asyncio.to_thread(request.app.state.xdr.entity_alerts, entity_id, period, page, page_size)
    return response({"total": total, "page": page, "pageSize": page_size, "period": period, "items": items})


USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@app.get("/api/v1/config")
async def config_users(request: Request):
    return {"users": await asyncio.to_thread(request.app.state.cmdb.config_users)}


@app.get("/api/v1/config/{user_id}")
async def get_config(user_id: str, request: Request):
    if not USER_RE.fullmatch(user_id):
        raise HTTPException(400, "invalid user id")
    result = await asyncio.to_thread(request.app.state.cmdb.get_config, user_id)
    if result is None:
        raise HTTPException(404, "configuration not found")
    return result


@app.put("/api/v1/config/{user_id}")
async def put_config(user_id: str, payload: dict, request: Request):
    if not USER_RE.fullmatch(user_id):
        raise HTTPException(400, "invalid user id")
    if len(json.dumps(payload, ensure_ascii=False).encode()) > 1_048_576:
        raise HTTPException(413, "configuration exceeds 1 MiB")
    await asyncio.to_thread(request.app.state.cmdb.save_config, user_id, payload)
    return response({"userId": user_id}, "已保存")


@app.delete("/api/v1/config/{user_id}")
async def delete_config(user_id: str, request: Request):
    if not USER_RE.fullmatch(user_id):
        raise HTTPException(400, "invalid user id")
    await asyncio.to_thread(request.app.state.cmdb.delete_config, user_id)
    return response({"userId": user_id}, "已删除")


# ---- CMDB 纳管维护 CRUD（0911：维护页经由 AI 助手打开）----

ASSET_LAYERS = {"geo", "device", "app", "task"}
ASSET_STATES = {"online", "offline", "degraded", "busy"}
SERVICE_STATUSES = {"running", "stopped", "degraded"}
# users/attackers 为画像专属平面（仅画像层生成的 actor 实体使用），刻意不进资产 CRUD 白名单
CMDB_ZONES = {"business", "enterprise", "cn-public", "global-public"}
KIND_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# 实体类型白名单（与前端 src/shared/kinds.ts 38 类注册表保持一致），layer 为类型推荐层，资产实际所属层可独立设置。
# 后端此前只按正则放行，任意字符串都能写库；前端 kindDef() 遇到未知类型直接抛错、
# 应用启动即崩（e2e 曾因测试数据 kind='router' 写入库后整页白屏）。写入口守门，非法 400。
KIND_LAYER: dict[str, str] = {
    "idc": "geo", "cloud-idc": "geo", "org": "geo",
    # 0914 展示优化：塔台/飞机/住宅（地域层补充对象，前后端注册表同步）
    "tower": "geo", "aircraft": "geo", "residence": "geo",
    "terminal": "device", "server": "device", "gateway": "device", "firewall": "device",
    "netgap": "device", "cell-phone":"device", "dedicated-device": "device", "dedicated-line": "device",
    # 0921 实体安全画像：攻击者/用户终端（安全主体平面，仅在画像层生成，不可经资产 CRUD 写入）
    "attacker": "device", "user-terminal": "device",
    "enclave-idc": "device", "vps": "device", "residential-proxy": "device",
    "biz-app": "app", "biz-mgmt-terminal": "app", "data-collect": "app", "data-analysis": "app",
    "data-storage": "app", "arp-app": "app", "arp-service": "app", "vpn-service": "app",
    "transport-proxy": "app", "security-monitor": "app", "threat-response": "app",
    "vps-control": "app", "info-publish": "app", "website": "app", "website-sub": "app",
    "org-planning": "task", "production": "task", "sales": "task",
    "after-sales": "task", "ops": "task", "rd": "task",
}
PROTOCOL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,20}$")
IP_RE = re.compile(r"^[0-9A-Za-z.:/_-]{1,45}$")


def _body_size_guard(payload: dict) -> None:
    if len(json.dumps(payload, ensure_ascii=False).encode()) > 1_048_576:
        raise HTTPException(413, "request body exceeds 1 MiB")


def _validated_asset_row(body: dict) -> dict:
    """POST /api/v1/assets 请求体校验，返回规范化 row（含快照实体所需字段）。"""
    _body_size_guard(body)
    asset_id = body.get("id")
    if not isinstance(asset_id, str) or not USER_RE.fullmatch(asset_id):
        raise HTTPException(400, "invalid asset id")
    name = body.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise HTTPException(400, "invalid asset name")
    kind = body.get("kind")
    if not isinstance(kind, str) or not KIND_RE.fullmatch(kind):
        raise HTTPException(400, "invalid asset kind")
    if kind not in KIND_LAYER:
        raise HTTPException(400, f"unknown asset kind: {kind}")
    layer = body.get("layer")
    if layer not in ASSET_LAYERS:
        raise HTTPException(400, f"invalid layer: {layer}")
    state = body.get("state", "online")
    if state not in ASSET_STATES:
        raise HTTPException(400, f"invalid state: {state}")
    zone = body.get("zone")
    if zone is not None and zone not in CMDB_ZONES:
        raise HTTPException(400, f"invalid zone: {zone}")
    if layer != "geo" and zone is None:
        raise HTTPException(400, "non-geo asset requires zone")
    ip_address = body.get("ip")
    if ip_address is not None and (not isinstance(ip_address, str) or not IP_RE.fullmatch(ip_address)):
        raise HTTPException(400, "invalid ip")
    attributes = body.get("attributes", {})
    if not isinstance(attributes, dict) or any(not isinstance(k, str) for k in attributes):
        raise HTTPException(400, "attributes must be a string-keyed object")
    for key, value in attributes.items():
        if not isinstance(value, (str, int, float, bool)):
            raise HTTPException(400, f"attribute value must be scalar: {key}")
    row: dict = {
        "id": asset_id, "name": name.strip(), "kind": kind, "layer": layer,
        "zone": zone if layer != "geo" else None, "state": state,
        "ip": ip_address, "attributes": attributes,
    }
    if layer == "geo":
        lat, lng = body.get("geoLat"), body.get("geoLng")
        if not isinstance(lat, (int, float)) or isinstance(lat, bool) or not isinstance(lng, (int, float)) or isinstance(lng, bool):
            raise HTTPException(400, "geo asset requires geoLat/geoLng")
        if not -90 <= lat <= 90 or not -180 <= lng <= 180:
            raise HTTPException(400, "geo out of range")
        row["geoLat"] = float(lat)
        row["geoLng"] = float(lng)
    return row


def _validated_asset_patch(body: dict) -> dict:
    """PUT /api/v1/assets/{id} 部分更新校验（仅 id 不可修改，layer/kind 独立校验）。"""
    _body_size_guard(body)
    for banned in ("id",):
        if banned in body:
            raise HTTPException(400, f"{banned} is immutable for existing assets")
    patch: dict = {}
    if "kind" in body:
        kind = body["kind"]
        if not isinstance(kind, str) or kind not in KIND_LAYER:
            raise HTTPException(400, "unknown asset kind")
        patch["kind"] = kind
    if "layer" in body:
        layer = body["layer"]
        if not isinstance(layer, str) or layer not in ASSET_LAYERS:
            raise HTTPException(400, "invalid layer")
        patch["layer"] = layer
    for key, limit in (("geoLat", 90), ("geoLng", 180)):
        if key in body:
            value = body[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not -limit <= value <= limit:
                raise HTTPException(400, f"invalid {key}")
            patch[key] = float(value)
    if "name" in body:
        name = body["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise HTTPException(400, "invalid asset name")
        patch["name"] = name.strip()
    if "state" in body:
        if body["state"] not in ASSET_STATES:
            raise HTTPException(400, f"invalid state: {body['state']}")
        patch["state"] = body["state"]
    if "zone" in body:
        zone = body["zone"]
        if not isinstance(zone, str) or zone not in CMDB_ZONES:
            raise HTTPException(400, f"invalid zone: {zone}")
        patch["zone"] = zone
    if "ip" in body:
        ip_address = body["ip"]
        if ip_address is not None and (not isinstance(ip_address, str) or not IP_RE.fullmatch(ip_address)):
            raise HTTPException(400, "invalid ip")
        patch["ip"] = ip_address
    if "attributes" in body:
        attributes = body["attributes"]
        if not isinstance(attributes, dict) or any(not isinstance(k, str) or not isinstance(v, (str, int, float, bool)) for k, v in attributes.items()):
            raise HTTPException(400, "invalid attributes")
        patch["attributes"] = attributes
    if not patch:
        raise HTTPException(400, "no editable field provided")
    return patch


def _validated_service_row(body: dict) -> dict:
    _body_size_guard(body)
    service_id = body.get("id")
    if not isinstance(service_id, str) or not USER_RE.fullmatch(service_id):
        raise HTTPException(400, "invalid service id")
    name = body.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise HTTPException(400, "invalid service name")
    asset_id = body.get("assetId")
    if not isinstance(asset_id, str) or not USER_RE.fullmatch(asset_id):
        raise HTTPException(400, "invalid assetId")
    protocol = body.get("protocol", "tcp")
    if not isinstance(protocol, str) or not PROTOCOL_RE.fullmatch(protocol):
        raise HTTPException(400, "invalid protocol")
    port = body.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise HTTPException(400, "invalid port")
    status = body.get("status", "running")
    if status not in SERVICE_STATUSES:
        raise HTTPException(400, f"invalid status: {status}")
    config = body.get("config", {})
    if not isinstance(config, dict):
        raise HTTPException(400, "config must be an object")
    return {"id": service_id, "name": name.strip(), "assetId": asset_id, "protocol": protocol.lower(), "port": port, "status": status, "config": config}


def _validated_service_patch(body: dict) -> dict:
    _body_size_guard(body)
    for banned in ("id",):
        if banned in body:
            raise HTTPException(400, f"{banned} is immutable for existing services")
    patch: dict = {}
    if "name" in body:
        name = body["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise HTTPException(400, "invalid service name")
        patch["name"] = name.strip()
    if "assetId" in body:
        asset_id = body["assetId"]
        if not isinstance(asset_id, str) or not USER_RE.fullmatch(asset_id):
            raise HTTPException(400, "invalid assetId")
        patch["assetId"] = asset_id
    if "protocol" in body:
        protocol = body["protocol"]
        if not isinstance(protocol, str) or not PROTOCOL_RE.fullmatch(protocol):
            raise HTTPException(400, "invalid protocol")
        patch["protocol"] = protocol.lower()
    if "port" in body:
        port = body["port"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise HTTPException(400, "invalid port")
        patch["port"] = port
    if "status" in body:
        if body["status"] not in SERVICE_STATUSES:
            raise HTTPException(400, f"invalid status: {body['status']}")
        patch["status"] = body["status"]
    if "config" in body:
        if not isinstance(body["config"], dict):
            raise HTTPException(400, "config must be an object")
        patch["config"] = body["config"]
    if not patch:
        raise HTTPException(400, "no editable field provided")
    return patch


@app.post("/api/v1/assets")
async def create_asset(payload: dict, request: Request):
    row = _validated_asset_row(payload)
    try:
        await asyncio.to_thread(request.app.state.cmdb.create_asset, row)
    except ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    return response({"id": row["id"]}, "已创建")


@app.put("/api/v1/assets/{asset_id}")
async def update_asset(asset_id: str, payload: dict, request: Request):
    if not USER_RE.fullmatch(asset_id):
        raise HTTPException(400, "invalid asset id")
    patch = _validated_asset_patch(payload)
    try:
        await asyncio.to_thread(request.app.state.cmdb.update_asset, asset_id, patch)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    return response({"id": asset_id}, "已保存")


@app.delete("/api/v1/assets/{asset_id}")
async def delete_asset(asset_id: str, request: Request):
    if not USER_RE.fullmatch(asset_id):
        raise HTTPException(400, "invalid asset id")
    try:
        await asyncio.to_thread(request.app.state.cmdb.delete_asset, asset_id)
    except NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    return response({"id": asset_id}, "已删除")


@app.post("/api/v1/services")
async def create_service(payload: dict, request: Request):
    row = _validated_service_row(payload)
    try:
        await asyncio.to_thread(request.app.state.cmdb.create_service, row)
    except NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    return response({"id": row["id"]}, "已创建")


@app.put("/api/v1/services/{service_id}")
async def update_service(service_id: str, payload: dict, request: Request):
    if not USER_RE.fullmatch(service_id):
        raise HTTPException(400, "invalid service id")
    patch = _validated_service_patch(payload)
    try:
        await asyncio.to_thread(request.app.state.cmdb.update_service, service_id, patch)
    except NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    return response({"id": service_id}, "已保存")


@app.delete("/api/v1/services/{service_id}")
async def delete_service(service_id: str, request: Request):
    if not USER_RE.fullmatch(service_id):
        raise HTTPException(400, "invalid service id")
    try:
        await asyncio.to_thread(request.app.state.cmdb.delete_service, service_id)
    except NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    return response({"id": service_id}, "已删除")


# ---- CMDB 纳管维护：批量导入 / 批量删除（0911 修正 2/3）----


def _validated_import_items(payload: dict, validator, label: str) -> list[dict]:
    """批量导入公共校验：items 为非空数组（≤1000），逐项校验并把索引并入错误信息。"""
    _body_size_guard(payload)
    items = payload.get("items")
    if not isinstance(items, list) or not items or len(items) > 1000:
        raise HTTPException(400, "items must be a non-empty array (≤1000)")
    rows: list[dict] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise HTTPException(400, f"items[{idx}] must be an object")
        try:
            rows.append(validator(item))
        except HTTPException as exc:
            raise HTTPException(400, f"items[{idx}]: {exc.detail}") from exc
    return rows


def _validated_batch_ids(payload: dict, label: str) -> list[str]:
    """批量删除公共校验：ids 为非空数组（≤500），逐项 ID 正则，去重保持顺序。"""
    _body_size_guard(payload)
    ids = payload.get("ids")
    if not isinstance(ids, list) or not ids or len(ids) > 500:
        raise HTTPException(400, "ids must be a non-empty array (≤500)")
    if any(not isinstance(i, str) or not USER_RE.fullmatch(i) for i in ids):
        raise HTTPException(400, f"invalid {label} id in ids")
    return list(dict.fromkeys(ids))


@app.post("/api/v1/assets/import")
async def import_assets(payload: dict, request: Request):
    rows = _validated_import_items(payload, _validated_asset_row, "asset")
    result = await asyncio.to_thread(request.app.state.cmdb.import_assets, rows)
    return response(result, f"导入完成：成功 {result['created']} 条，跳过 {len(result['skipped'])} 条")


@app.post("/api/v1/services/import")
async def import_services(payload: dict, request: Request):
    rows = _validated_import_items(payload, _validated_service_row, "service")
    result = await asyncio.to_thread(request.app.state.cmdb.import_services, rows)
    return response(result, f"导入完成：成功 {result['created']} 条，跳过 {len(result['skipped'])} 条")


@app.post("/api/v1/assets/batch-delete")
async def batch_delete_assets(payload: dict, request: Request):
    ids = _validated_batch_ids(payload, "asset")
    result = await asyncio.to_thread(request.app.state.cmdb.batch_delete_assets, ids)
    return response(result, f"批量删除完成：删除 {result['deleted']} 条，失败 {len(result['failed'])} 条")


@app.post("/api/v1/services/batch-delete")
async def batch_delete_services(payload: dict, request: Request):
    ids = _validated_batch_ids(payload, "service")
    result = await asyncio.to_thread(request.app.state.cmdb.batch_delete_services, ids)
    return response(result, f"批量删除完成：删除 {result['deleted']} 条，失败 {len(result['failed'])} 条")


@app.get("/api/events")
async def events(request: Request, snapshot: bool = False) -> StreamingResponse:
    async def stream() -> AsyncIterator[str]:
        seq = int(request.headers.get("last-event-id", "0") or 0)
        sent_ids: set[str] = set()
        if snapshot:
            rows = await asyncio.to_thread(request.app.state.xdr.active_alerts)
            for row in reversed(rows):
                sent_ids.add(row["uid"])
                seq += 1
                envelope = alert_event(row, seq)
                yield f"id: {seq}\nevent: snapshot\ndata: {json.dumps(envelope, ensure_ascii=False, default=str)}\n\n"
        while not await request.is_disconnected():
            rows = await asyncio.to_thread(request.app.state.xdr.recent_events, 30)
            new_rows = [row for row in rows if row["uid"] not in sent_ids]
            for row in new_rows:
                sent_ids.add(row["uid"])
                seq += 1
                envelope = alert_event(row, seq)
                yield f"id: {seq}\ndata: {json.dumps(envelope, ensure_ascii=False, default=str)}\n\n"
            # 新告警命中实体 → 失效对应画像缓存；涉及 IP 证据 → 失效 actor 缓存（下一轮 worker 重建）
            if new_rows and request.app.state.profiling is not None:
                entity_ids = {row.get("entity_id") or "" for row in new_rows}
                request.app.state.profiling.invalidate_entities(entity_ids)
                request.app.state.profiling.cache.invalidate("actors")
            yield ": heartbeat\n\n"
            await asyncio.sleep(settings.sse_poll_seconds)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
