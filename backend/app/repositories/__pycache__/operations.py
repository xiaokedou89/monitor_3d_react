"""实体胶囊、不可变报告证据及研判闭环。所有操作按用户和数据模式隔离。"""
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4


def decode(value):
    return json.loads(value) if isinstance(value, str) else value


def encoded(value):
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True, separators=(",", ":"))


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class OperationConflict(ValueError):
    pass


class OperationsRepository:
    def __init__(self, db):
        self.db = db

    def initialize(self):
        statements = [
            """CREATE TABLE IF NOT EXISTS entity_capsules (
                user_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL, mode VARCHAR(12) NOT NULL,
                entity_id VARCHAR(200) NOT NULL, materials JSON NOT NULL,
                updated_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                PRIMARY KEY(user_id,mode,entity_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
            """CREATE TABLE IF NOT EXISTS security_reports (
                id CHAR(36) PRIMARY KEY,user_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,mode VARCHAR(12) NOT NULL,
                entity_id VARCHAR(200) NOT NULL,title VARCHAR(200) NOT NULL,body MEDIUMTEXT NOT NULL,
                evidence JSON NOT NULL,evidence_hash CHAR(64) NOT NULL,model VARCHAR(200) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'review',owner VARCHAR(128) NOT NULL DEFAULT '',
                classification JSON NOT NULL,audit JSON NOT NULL,revision INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6),
                INDEX report_entity(user_id,mode,entity_id,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
            """CREATE TABLE IF NOT EXISTS analysis_jobs (
                id CHAR(36) PRIMARY KEY,user_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,mode VARCHAR(12) NOT NULL,
                entity_id VARCHAR(200) NOT NULL,status VARCHAR(20) NOT NULL,progress VARCHAR(200) NOT NULL,
                input JSON NOT NULL,error TEXT,report_id CHAR(36),
                created_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6),updated_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                INDEX jobs_pending(status,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
            """CREATE TABLE IF NOT EXISTS message_reviews (
                user_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,mode VARCHAR(12) NOT NULL,
                entity_id VARCHAR(200) NOT NULL,message_id VARCHAR(240) NOT NULL,
                status VARCHAR(20) NOT NULL,report_id CHAR(36),
                PRIMARY KEY(user_id,mode,entity_id,message_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
        ]
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            for statement in statements:
                cursor.execute(statement)
            cursor.execute("ALTER TABLE message_reviews MODIFY message_id VARCHAR(240) NOT NULL")
            cursor.execute("UPDATE analysis_jobs SET status='failed',error='服务重启中断了生成，证据仍保留在胶囊中，可重新生成。' WHERE status='running'")
            cursor.close()

    def capsules(self, user, mode):
        with self.db.mysql() as conn:
            c = conn.cursor(dictionary=True)
            c.execute("SELECT entity_id AS entityId,JSON_LENGTH(materials) AS count,updated_at AS updatedAt FROM entity_capsules WHERE user_id=%s AND mode=%s AND JSON_LENGTH(materials)>0 ORDER BY updated_at DESC", (user, mode))
            rows = c.fetchall(); c.close()
        return rows

    def capsule(self, user, mode, entity):
        with self.db.mysql() as conn:
            c = conn.cursor(dictionary=True)
            c.execute("SELECT materials,updated_at AS updatedAt FROM entity_capsules WHERE user_id=%s AND mode=%s AND entity_id=%s", (user, mode, entity))
            row = c.fetchone(); c.close()
        return {"entityId": entity, "materials": decode(row["materials"]) if row else [], "updatedAt": row["updatedAt"] if row else None}

    def change_material(self, user, mode, entity, material=None, remove_id=None):
        with self.db.mysql() as conn:
            conn.start_transaction()
            c = conn.cursor(dictionary=True)
            try:
                c.execute("INSERT IGNORE INTO entity_capsules(user_id,mode,entity_id,materials) VALUES(%s,%s,%s,'[]')", (user, mode, entity))
                c.execute("SELECT materials FROM entity_capsules WHERE user_id=%s AND mode=%s AND entity_id=%s FOR UPDATE", (user, mode, entity))
                items = decode(c.fetchone()["materials"])
                if remove_id:
                    items = [m for m in items if m["id"] != remove_id]
                    c.execute("DELETE FROM message_reviews WHERE user_id=%s AND mode=%s AND entity_id=%s AND message_id=%s AND status='collected'", (user, mode, entity, remove_id.removeprefix("alert:")))
                if material and not any(m["id"] == material["id"] for m in items):
                    if len(items) >= 500:
                        raise OperationConflict("一个胶囊最多收集 500 项，请先归档本轮分析。")
                    items.append(material)
                    if len(encoded(items).encode()) > 4_194_304:
                        raise OperationConflict("胶囊材料总量不能超过 4 MiB，请先归档。")
                    if material["kind"] == "alert":
                        c.execute("""INSERT INTO message_reviews(user_id,mode,entity_id,message_id,status) VALUES(%s,%s,%s,%s,'collected')
                            ON DUPLICATE KEY UPDATE status='collected',report_id=NULL""", (user, mode, entity, material["message"]["id"]))
                c.execute("UPDATE entity_capsules SET materials=%s WHERE user_id=%s AND mode=%s AND entity_id=%s", (encoded(items), user, mode, entity))
                conn.commit()
            except Exception:
                conn.rollback(); raise
            finally:
                c.close()
        return self.capsule(user, mode, entity)

    def message_ids(self, user, mode, status):
        with self.db.mysql() as conn:
            c = conn.cursor()
            c.execute("SELECT DISTINCT message_id FROM message_reviews WHERE user_id=%s AND mode=%s AND status=%s", (user, mode, status))
            ids = [r[0] for r in c.fetchall()]; c.close()
        return ids

    def start_job(self, user, mode, entity, entity_data, use_ai):
        with self.db.mysql() as conn:
            conn.start_transaction(); c = conn.cursor(dictionary=True)
            try:
                c.execute("SELECT materials FROM entity_capsules WHERE user_id=%s AND mode=%s AND entity_id=%s FOR UPDATE", (user, mode, entity))
                row = c.fetchone()
                if not row or not decode(row["materials"]):
                    raise OperationConflict("胶囊为空，请先收集证据。")
                c.execute("SELECT id FROM analysis_jobs WHERE user_id=%s AND mode=%s AND entity_id=%s AND status IN ('queued','running')", (user, mode, entity))
                pending = c.fetchone()
                if pending:
                    conn.commit(); return pending["id"]
                id = str(uuid4())
                data = {"entity": entity_data, "materials": decode(row["materials"]), "ai": use_ai, "capturedAt": utcnow()}
                c.execute("INSERT INTO analysis_jobs(id,user_id,mode,entity_id,status,progress,input) VALUES(%s,%s,%s,%s,'queued','已固定本轮证据，等待分析',%s)", (id, user, mode, entity, encoded(data)))
                conn.commit(); return id
            except Exception:
                conn.rollback(); raise
            finally: c.close()

    def progress(self, id, text):
        with self.db.mysql() as conn:
            c = conn.cursor()
            c.execute("UPDATE analysis_jobs SET progress=%s WHERE id=%s AND status='running'", (text[:200], id))
            c.close()

    def claim_job(self):
        with self.db.mysql() as conn:
            conn.start_transaction(); c = conn.cursor(dictionary=True)
            try:
                c.execute("SELECT * FROM analysis_jobs WHERE status='queued' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED")
                row = c.fetchone()
                if row:
                    c.execute("UPDATE analysis_jobs SET status='running',progress='正在分析固定的证据快照' WHERE id=%s", (row["id"],))
                    row["input"] = decode(row["input"])
                conn.commit(); return row
            except Exception:
                conn.rollback(); raise
            finally: c.close()

    def job(self, user, mode, id=None, entity=None):
        with self.db.mysql() as conn:
            c = conn.cursor(dictionary=True)
            c.execute("SELECT id,status,progress,error,report_id AS reportId FROM analysis_jobs WHERE user_id=%s AND mode=%s AND " +
                      ("id=%s" if id else "entity_id=%s ORDER BY created_at DESC LIMIT 1"), (user, mode, id or entity))
            row = c.fetchone(); c.close()
        return row

    def fail_job(self, id, error):
        with self.db.mysql() as conn:
            c = conn.cursor(); c.execute("UPDATE analysis_jobs SET status='failed',progress='生成失败，胶囊材料保留',error=%s WHERE id=%s", (error[:2000], id)); c.close()

    def archive_job(self, job, body, model):
        """写报告、绑定证据、移出已归档材料和任务完成为同一个事务。"""
        evidence = job["input"]
        user, mode, entity, id = job["user_id"], job["mode"], job["entity_id"], job["id"]
        with self.db.mysql() as conn:
            conn.start_transaction(); c = conn.cursor(dictionary=True)
            try:
                c.execute("SELECT materials FROM entity_capsules WHERE user_id=%s AND mode=%s AND entity_id=%s FOR UPDATE", (user, mode, entity))
                current = decode(c.fetchone()["materials"])
                captured = {m["id"]: m for m in evidence["materials"]}
                remaining = [m for m in current if captured.get(m["id"]) != m]
                title = f"{evidence['entity'].get('name', entity)} · 安全关联分析"[:200]
                audit = [{"at": utcnow(), "actor": user, "status": "review", "note": "报告与证据快照归档，等待人工复核。"}]
                digest = hashlib.sha256(encoded(evidence).encode()).hexdigest()
                c.execute("""INSERT INTO security_reports(id,user_id,mode,entity_id,title,body,evidence,evidence_hash,model,classification,audit)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'[]',%s)""", (id, user, mode, entity, title, body, encoded(evidence), digest, model, encoded(audit)))
                c.execute("UPDATE entity_capsules SET materials=%s WHERE user_id=%s AND mode=%s AND entity_id=%s", (encoded(remaining), user, mode, entity))
                for m in evidence["materials"]:
                    if m["kind"] == "alert" and not any(n["id"] == m["id"] for n in remaining):
                        c.execute("UPDATE message_reviews SET status='review',report_id=%s WHERE user_id=%s AND mode=%s AND entity_id=%s AND message_id=%s", (id, user, mode, entity, m["message"]["id"]))
                c.execute("UPDATE analysis_jobs SET status='complete',progress='报告与证据已归档',report_id=%s WHERE id=%s", (id, id))
                conn.commit()
            except Exception:
                conn.rollback(); raise
            finally: c.close()

    def reports(self, user, mode, entity):
        with self.db.mysql() as conn:
            c = conn.cursor(dictionary=True)
            c.execute("SELECT id,title,status,owner,model,created_at AS createdAt FROM security_reports WHERE user_id=%s AND mode=%s AND entity_id=%s ORDER BY created_at DESC", (user, mode, entity))
            rows = c.fetchall(); c.close()
        return rows

    def report(self, user, mode, id):
        with self.db.mysql() as conn:
            c = conn.cursor(dictionary=True)
            c.execute("SELECT id,entity_id AS entityId,title,body,evidence,evidence_hash AS evidenceHash,model,status,owner,classification,audit,revision,created_at AS createdAt FROM security_reports WHERE user_id=%s AND mode=%s AND id=%s", (user, mode, id))
            row = c.fetchone(); c.close()
        if row:
            for key in ("evidence", "classification", "audit"): row[key] = decode(row[key])
        return row

    def transition(self, user, mode, id, patch):
        allowed = {"review": {"handling"}, "handling": {"verify"}, "verify": {"closed", "handling"}, "closed": {"handling"}}
        with self.db.mysql() as conn:
            conn.start_transaction(); c = conn.cursor(dictionary=True)
            try:
                c.execute("SELECT status,audit,revision FROM security_reports WHERE user_id=%s AND mode=%s AND id=%s FOR UPDATE", (user, mode, id))
                old = c.fetchone()
                if not old: raise KeyError(id)
                if old["revision"] != patch["revision"]: raise OperationConflict("报告已更新，请重新打开后操作。")
                if patch["status"] not in allowed[old["status"]]: raise OperationConflict("不允许跳过复核、处置或验证环节。")
                audit = decode(old["audit"]) + [{"at": utcnow(), "actor": user, **{k: patch[k] for k in ("status", "owner", "classification", "note")}}]
                c.execute("UPDATE security_reports SET status=%s,owner=%s,classification=%s,audit=%s,revision=revision+1 WHERE user_id=%s AND mode=%s AND id=%s", (patch["status"], patch["owner"], encoded(patch["classification"]), encoded(audit), user, mode, id))
                c.execute("UPDATE message_reviews SET status=%s WHERE user_id=%s AND mode=%s AND report_id=%s", (patch["status"], user, mode, id))
                conn.commit()
            except Exception:
                conn.rollback(); raise
            finally: c.close()
        return self.report(user, mode, id)
