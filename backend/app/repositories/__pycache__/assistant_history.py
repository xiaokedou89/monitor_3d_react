import json
from uuid import UUID


class HistoryConflict(Exception):
    pass


class AssistantHistoryRepository:
    def __init__(self, db):
        self.db = db

    def initialize(self):
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE IF NOT EXISTS assistant_conversations (
                user_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
                conversation_id CHAR(36) NOT NULL,
                title VARCHAR(200) NOT NULL,
                messages JSON NOT NULL,
                revision INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                PRIMARY KEY(user_id, conversation_id),
                INDEX assistant_history_updated(user_id, updated_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
            cursor.close()

    def list(self, user_id, offset=0, limit=50):
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT COUNT(*) AS total FROM assistant_conversations WHERE user_id=%s", (user_id,))
            total = cursor.fetchone()["total"]
            cursor.execute("""SELECT conversation_id AS id,title,revision,created_at AS createdAt,updated_at AS updatedAt
                FROM assistant_conversations WHERE user_id=%s ORDER BY updated_at DESC,conversation_id LIMIT %s OFFSET %s""",
                           (user_id, limit, offset))
            items = cursor.fetchall()
            cursor.close()
        return {"items": items, "total": total}

    def get(self, user_id, conversation_id):
        with self.db.mysql() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""SELECT conversation_id AS id,title,messages,revision,created_at AS createdAt,updated_at AS updatedAt
                FROM assistant_conversations WHERE user_id=%s AND conversation_id=%s""", (user_id, str(conversation_id)))
            row = cursor.fetchone()
            cursor.close()
        if row and isinstance(row["messages"], str):
            row["messages"] = json.loads(row["messages"])
        return row

    def save(self, user_id, conversation_id: UUID, title, messages, revision):
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            try:
                if revision == 0:
                    # INSERT IGNORE 仅用于并发首次创建冲突；所有长度/JSON 均在 API 入口校验。
                    cursor.execute("""INSERT IGNORE INTO assistant_conversations
                        (user_id,conversation_id,title,messages,revision) VALUES(%s,%s,%s,%s,1)""",
                                   (user_id, str(conversation_id), title, json.dumps(messages, ensure_ascii=False)))
                else:
                    cursor.execute("""UPDATE assistant_conversations SET title=%s,messages=%s,revision=revision+1
                        WHERE user_id=%s AND conversation_id=%s AND revision=%s""",
                                   (title, json.dumps(messages, ensure_ascii=False), user_id, str(conversation_id), revision))
                if cursor.rowcount != 1:
                    raise HistoryConflict("该会话已在其他页面更新或删除，请保留当前内容后重新加载历史。")
                return {"revision": revision + 1}
            finally:
                cursor.close()

    def delete(self, user_id, conversation_id):
        with self.db.mysql() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM assistant_conversations WHERE user_id=%s AND conversation_id=%s", (user_id, str(conversation_id)))
            deleted = cursor.rowcount > 0
            cursor.close()
        return deleted
