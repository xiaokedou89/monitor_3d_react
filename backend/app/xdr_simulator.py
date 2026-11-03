import json
import random
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
DATA_FILE = ROOT / "backend/runtime/xdr-simulator.json"
TOKEN = "internal-debug-token"
lock = threading.Lock()

app = FastAPI(title="XDR API Simulator", version="1.0.0")


class GenerateRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    entity_id: str | None = None
    relation_id: str | None = None
    level: str | None = Field(default=None, pattern="^[0-4]$")
    category: str = Field(default="attack", pattern="^(attack|violation|blocked|system|attack-internal|attack-public)$")
    source_type: str | None = None
    # 0921 画像夹具字段（可选，缺省保持既有随机行为，向后兼容）
    log_kind: str | None = Field(default=None, pattern="^(safe|stream|honey_pot|edr|netctrl_violation|netctrl_block)$")
    attacker_ip: str | None = None
    attacker_geo: str | None = None
    att_ck: str | list[str] | None = None
    cve: str | list[str] | None = None
    attack_steps: str | None = None
    event_name: str | None = None


# log_kind → 默认 source_type（docs/13 §3.4.3 类别口径：bedi_dou→netctrl_violation）
LOG_KIND_SOURCE = {
    "safe": "safe", "stream": "stream", "honey_pot": "honeypot", "edr": "edr",
    "netctrl_violation": "netctrl_violation", "netctrl_block": "netctrl_block",
}

# search 分流：type=1 安全日志按 log_kind 归桶（collector 按桶名映射 source/category）
KIND_BUCKETS_TYPE1 = {
    "safe": "safe_list", "edr": "edr_list", "attack": "attack_list",
    "honey_pot": "honey_pot_list", "netctrl_violation": "bedi_dou_list",
    "netctrl_block": "safe_list",  # 阻断告警保持走 safe 桶（collector 按 category 区分）
}


def load_records() -> list[dict[str, Any]]:
    if not DATA_FILE.exists():
        return []
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def save_records(records: list[dict[str, Any]]) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = DATA_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(records[-10000:], ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(DATA_FILE)


def require_auth(authorization: str | None) -> None:
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "invalid simulator token")


def parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def dataset_refs() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dataset = json.loads((ROOT / "public/data/dataset.json").read_text(encoding="utf-8"))
    # 受害者候选排除画像专属安全主体（攻击者/用户终端是主体，不是受害资产）
    entities = [e for e in dataset["entities"]
                if e["layer"] in {"device", "app"} and e["kind"] not in {"attacker", "user-terminal"}]
    return entities, dataset["relations"]


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "records": len(load_records())}


@app.post("/simulator/generate")
def generate(body: GenerateRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_auth(authorization)
    entities, relations = dataset_refs()
    now = datetime.now().astimezone()
    titles = ["异常外联行为", "SQL 注入尝试", "横向移动检测", "弱口令登录", "恶意文件传播"]
    created: list[dict[str, Any]] = []
    for index in range(body.count):
        entity = next((e for e in entities if e["id"] == body.entity_id), None) or random.choice(entities)
        relation = next((r for r in relations if r["id"] == body.relation_id), None)
        if relation is None:
            relation = next((r for r in relations if r["from"] == entity["id"] or r["to"] == entity["id"]), random.choice(relations))
        uid = f"xdr-sim-{now:%Y%m%d%H%M%S%f}-{index}-{uuid.uuid4().hex[:6]}"
        source_ip = body.attacker_ip or f"172.20.{random.randint(1, 250)}.{random.randint(1, 250)}"
        destination_ip = f"10.20.{random.randint(1, 250)}.{random.randint(1, 250)}"
        # 0910 内网/公网拆分：攻击告警按受害实体所在 zone 判定（公网区→attack-public）
        victim_public = entity.get("zone") in {"cn-public", "global-public"}
        if body.category == "attack":
            category = "attack-public" if victim_public else "attack-internal"
        else:
            category = body.category
        log_kind = body.log_kind or ("stream" if category == "system" else "safe")
        source_type = body.source_type or LOG_KIND_SOURCE.get(log_kind, "safe")
        record = {
            "log_kind": log_kind, "alert_category": category, "source_type": source_type, "uid": uid,
            "node_name": "xdr-simulator", "event_name": body.event_name or random.choice(titles),
            "event_time": now.strftime("%Y-%m-%d %H:%M:%S"), "event_level": body.level or random.choice(["1", "2", "3"]),
            "device_name": entity["name"], "platform_device_name": "simulator-engine", "protocol": "tcp",
            "attacker_host": {"ip": source_ip, "geo_location": body.attacker_geo or "模拟外部网络", "safety_tag": "外网", "asset_tag": ""},
            "attacker_port": str(random.randint(20000, 60000)),
            "victim_host": {"ip": destination_ip, "geo_location": "模拟公网区" if victim_public else "模拟业务网", "safety_tag": "外网" if victim_public else "内网", "asset_tag": entity["name"]},
            "victim_port": str(random.choice([22, 443, 3306, 8080])), "event_type1": "安全威胁", "event_type2": "模拟攻击",
            "attack_steps": body.attack_steps or "初始访问", "event_result": "待核查", "disposal_state": "active",
            "entity_id": entity["id"], "relation_id": relation["id"],
        }
        # 画像证据字段：att_ck/cve 直接入 raw_json（仓储层 CVE/ATT&CK 抽取 SQL 消费）
        if body.att_ck is not None:
            record["att_ck"] = body.att_ck
        if body.cve is not None:
            record["cve"] = body.cve
        created.append(record)
    with lock:
        records = load_records()
        records.extend(created)
        save_records(records)
    return {"code": 0, "msg": "success", "data": {"count": len(created), "items": created}}


def filtered(body: dict[str, Any], kinds: set[str]) -> list[dict[str, Any]]:
    start = parse_time(body.get("start_date"), datetime.min)
    end = parse_time(body.get("end_date"), datetime.max)
    rows = [r for r in load_records() if r.get("log_kind", "safe") in kinds
            and start <= datetime.strptime(r["event_time"], "%Y-%m-%d %H:%M:%S") <= end]
    rows.sort(key=lambda row: row["event_time"], reverse=body.get("time_sort", 2) == 2)
    return rows


@app.post("/api/v1/logweb/threatanalysis-logretrieval/search")
async def search(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_auth(authorization)
    body = await request.json()
    if body.get("type") == 2:
        rows = filtered(body, {"stream"})
        lists = {"stream_list": rows}
    else:
        rows = filtered(body, set(KIND_BUCKETS_TYPE1))
        lists = {bucket: [r for r in rows if KIND_BUCKETS_TYPE1[r.get("log_kind", "safe")] == bucket]
                 for bucket in ("safe_list", "edr_list", "attack_list", "honey_pot_list", "bedi_dou_list")}
    page = max(int(body.get("page", 1)), 1)
    size = min(max(int(body.get("page_size", 20)), 1), 500)
    page_rows = {key: rows[(page - 1) * size:page * size] for key, rows in lists.items()}
    return {"code": 0, "msg": "success", "data": {
        "safe_list": [], "stream_list": [], "attack_list": [], "honey_pot_list": [], "bedi_dou_list": [], "edr_list": [],
        **page_rows,
    }}


@app.post("/api/v1/logweb/threatanalysis-logretrieval/search-total")
async def search_total(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_auth(authorization)
    body = await request.json()
    kinds = {"stream"} if body.get("type") == 2 else set(KIND_BUCKETS_TYPE1)
    return {"code": 0, "msg": "success", "data": {"total": len(filtered(body, kinds))}}


@app.post("/api/v1/logweb/threatanalysis-logretrieval/search-rawlog")
async def rawlog(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_auth(authorization)
    body = await request.json()
    row = next((item for item in load_records() if item["uid"] == body.get("id")), None)
    if row is None:
        raise HTTPException(404, "log not found")
    return {"code": 0, "msg": "success", "data": {"raw_log": json.dumps(row, ensure_ascii=False)}}
