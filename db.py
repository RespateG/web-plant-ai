"""SQLite 数据层：表结构、旧 JSON 数据迁移、业务读写。

设计要点：
- 每个请求独立连接，写操作统一走 BEGIN IMMEDIATE 事务，配合 WAL + busy_timeout
  避免原来的“整库读-改-写”并发覆盖问题。
- 首次启动时自动把 data/植物数据库.json 与 data/auth.json 迁移进 SQLite，
  迁移前先备份原始 JSON，原文件保留不删除。
- 旧版 todoDone 没有年月信息，迁移时归入当前月份。
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("PLANT_DATA_DIR") or os.path.join(BASE_DIR, "data")
DB_PATH = os.environ.get("PLANT_DB_PATH") or os.path.join(DATA_DIR, "plants.db")
LEGACY_JSON_PATH = os.environ.get("PLANT_LEGACY_JSON") or os.path.join(
    DATA_DIR, "植物数据库.json"
)
LEGACY_AUTH_PATH = os.environ.get("PLANT_LEGACY_AUTH") or os.path.join(
    DATA_DIR, "auth.json"
)
BACKUP_DIR = os.path.join(DATA_DIR, "backup")

SCHEMA_VERSION = 1
SESSION_TTL_DAYS = 30
PBKDF2_ITERATIONS = 260_000
MAX_BACKUPS = 20

PLANT_TEXT_FIELDS = (
    "area",
    "sow_time",
    "bloom_time",
    "description",
    "care",
    "disease",
    "img",
)

_init_lock = threading.Lock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS plants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    area        TEXT NOT NULL DEFAULT '',
    sow_time    TEXT NOT NULL DEFAULT '',
    bloom_time  TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    care        TEXT NOT NULL DEFAULT '',
    disease     TEXT NOT NULL DEFAULT '',
    img         TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plants_name ON plants(name);

CREATE TABLE IF NOT EXISTS user_plants (
    plant_id   TEXT PRIMARY KEY REFERENCES plants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS todo_done (
    plant_id TEXT NOT NULL REFERENCES plants(id) ON DELETE CASCADE,
    period   TEXT NOT NULL,
    done_at  TEXT NOT NULL,
    PRIMARY KEY (plant_id, period)
);
CREATE INDEX IF NOT EXISTS idx_todo_period ON todo_done(period);

CREATE TABLE IF NOT EXISTS diseases (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    symptom    TEXT NOT NULL DEFAULT '',
    treatment  TEXT NOT NULL DEFAULT '',
    prevention TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class DataError(Exception):
    """业务校验错误，main.py 会转换成 HTTP 400/404/409。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def now_iso() -> str:
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def current_period() -> str:
    return datetime.date.today().strftime("%Y-%m")


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def read_conn():
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction():
    """写事务：BEGIN IMMEDIATE 立即拿写锁，避免并发写互相覆盖。"""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def _backup_file(src: str, reason: str) -> Optional[str]:
    if not os.path.exists(src):
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"{reason}-{stamp}-{os.path.basename(src)}")
    shutil.copy2(src, dst)
    return dst


def backup_database(reason: str = "manual") -> Optional[str]:
    """用 SQLite 在线备份 API 生成一致性快照。"""
    if not os.path.exists(DB_PATH):
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst_path = os.path.join(BACKUP_DIR, f"plants-{stamp}-{reason}.db")
    with read_conn() as src:
        dst = sqlite3.connect(dst_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    _prune_backups()
    return dst_path


def _prune_backups():
    try:
        files = sorted(
            (
                os.path.join(BACKUP_DIR, f)
                for f in os.listdir(BACKUP_DIR)
                if f.endswith((".db", ".json"))
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        for old in files[MAX_BACKUPS:]:
            os.remove(old)
    except OSError:
        pass


def _create_schema(conn: sqlite3.Connection):
    # executescript 会隐式提交，因此只能在事务外调用
    conn.executescript(SCHEMA_SQL)
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def _migrate_schema(conn: sqlite3.Connection):
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"数据库版本 {version} 高于程序支持的 {SCHEMA_VERSION}，请升级程序"
        )
    # 脚本全部 IF NOT EXISTS，可安全重复执行，便于后续版本补表
    conn.executescript(SCHEMA_SQL)
    if version < SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def _meta_get(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def _meta_set(conn: sqlite3.Connection, key: str, value: str):
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def ensure_db() -> Dict[str, Any]:
    """初始化数据库；首次运行自动迁移旧 JSON。返回迁移摘要。"""
    with _init_lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        first_time = not os.path.exists(DB_PATH)
        conn = _connect()
        summary: Dict[str, Any] = {"first_time": first_time, "migrated": False}
        try:
            if first_time:
                _create_schema(conn)
            else:
                _migrate_schema(conn)

            conn.execute("BEGIN IMMEDIATE")
            try:
                if (
                    _meta_get(conn, "legacy_json_migrated") != "1"
                    and os.path.exists(LEGACY_JSON_PATH)
                ):
                    summary.update(_import_legacy_json(conn))
                    _meta_set(conn, "legacy_json_migrated", "1")
                    summary["migrated"] = True
                if (
                    _meta_get(conn, "legacy_auth_migrated") != "1"
                    and os.path.exists(LEGACY_AUTH_PATH)
                ):
                    summary.update(_import_legacy_auth(conn))
                    _meta_set(conn, "legacy_auth_migrated", "1")
                    summary["migrated"] = True
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
        finally:
            conn.close()
        return summary


def _str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _import_legacy_json(conn: sqlite3.Connection) -> Dict[str, Any]:
    """把旧 植物数据库.json 导入空库。保留全部条目（含历史重名）。"""
    backup = _backup_file(LEGACY_JSON_PATH, "legacy-json")
    try:
        with open(LEGACY_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"旧 JSON 数据读取失败：{exc}") from exc

    plants = data.get("plantList") or []
    user_ids = data.get("userPlantIdList") or []
    todo_ids = data.get("todoDone") or []
    ts = now_iso()
    period = current_period()

    inserted_plants = 0
    inserted_user = 0
    inserted_todo = 0
    valid_ids = set()
    for p in plants:
        if not isinstance(p, dict):
            continue
        pid = _str(p.get("id")).strip()
        name = _str(p.get("name")).strip()
        if not pid or not name or pid in valid_ids:
            continue
        conn.execute(
            """INSERT INTO plants
               (id,name,area,sow_time,bloom_time,description,care,disease,img,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                pid,
                name,
                _str(p.get("area")),
                _str(p.get("sowTime")),
                _str(p.get("bloomTime")),
                _str(p.get("desc")),
                _str(p.get("care")),
                _str(p.get("disease")),
                _str(p.get("img")),
                ts,
                ts,
            ),
        )
        valid_ids.add(pid)
        inserted_plants += 1

    for pid in user_ids:
        pid = _str(pid)
        if pid in valid_ids:
            cur = conn.execute(
                "INSERT OR IGNORE INTO user_plants(plant_id, created_at) VALUES (?,?)",
                (pid, ts),
            )
            inserted_user += cur.rowcount

    for pid in todo_ids:
        pid = _str(pid)
        if pid in valid_ids:
            cur = conn.execute(
                "INSERT OR IGNORE INTO todo_done(plant_id, period, done_at) VALUES (?,?,?)",
                (pid, period, ts),
            )
            inserted_todo += cur.rowcount

    return {
        "legacy_json_backup": backup,
        "plants": inserted_plants,
        "user_plants": inserted_user,
        "todo_done": inserted_todo,
        "todo_period": period,
    }


def _import_legacy_auth(conn: sqlite3.Connection) -> Dict[str, Any]:
    """迁移旧的单账号 auth.json，密码哈希保持旧 sha256，登录成功后自动升级。"""
    backup = _backup_file(LEGACY_AUTH_PATH, "legacy-auth")
    try:
        with open(LEGACY_AUTH_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"legacy_auth_backup": backup, "user": None}
    username = _str(data.get("username")).strip()
    password_hash = _str(data.get("password_hash")).strip()
    if not username or not password_hash:
        return {"legacy_auth_backup": backup, "user": None}
    conn.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, created_at) VALUES (?,?,?)",
        (username, password_hash, now_iso()),
    )
    return {"legacy_auth_backup": backup, "user": username}


# ---------------------------------------------------------------------------
# 密码与会话
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_b64, hash_b64 = stored.split("$", 3)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                base64.b64decode(salt_b64),
                int(iterations),
            )
            return hmac.compare_digest(dk, base64.b64decode(hash_b64))
        except (ValueError, TypeError):
            return False
    # 兼容旧版无盐 sha256
    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy, stored)


def password_needs_upgrade(stored: str) -> bool:
    return not stored.startswith("pbkdf2_sha256$")


def get_user(username: str) -> Optional[sqlite3.Row]:
    with read_conn() as conn:
        return conn.execute(
            "SELECT username, password_hash FROM users WHERE username=?", (username,)
        ).fetchone()


def has_user() -> bool:
    with read_conn() as conn:
        return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def create_user(username: str, password: str) -> None:
    with transaction() as conn:
        if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise DataError("已存在账号，禁止重复注册", 400)
        conn.execute(
            "INSERT INTO users(username, password_hash, created_at) VALUES (?,?,?)",
            (username, hash_password(password), now_iso()),
        )


def upgrade_password(username: str, password: str) -> None:
    with transaction() as conn:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (hash_password(password), username),
        )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (
        datetime.datetime.now() + datetime.timedelta(days=SESSION_TTL_DAYS)
    ).replace(microsecond=0).isoformat()
    with transaction() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
        conn.execute(
            "INSERT INTO sessions(token_hash, username, created_at, expires_at) VALUES (?,?,?,?)",
            (_token_hash(token), username, now_iso(), expires),
        )
    return token


def session_username(token: str) -> Optional[str]:
    if not token:
        return None
    with read_conn() as conn:
        row = conn.execute(
            "SELECT username FROM sessions WHERE token_hash=? AND expires_at > ?",
            (_token_hash(token), now_iso()),
        ).fetchone()
        return row["username"] if row else None


def delete_session(token: str) -> None:
    if not token:
        return
    with transaction() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))


# ---------------------------------------------------------------------------
# 植物 / 我的种植 / 待办
# ---------------------------------------------------------------------------


def _plant_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "area": row["area"],
        "sowTime": row["sow_time"],
        "bloomTime": row["bloom_time"],
        "desc": row["description"],
        "care": row["care"],
        "disease": row["disease"],
        "img": row["img"],
    }


def _disease_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "symptom": row["symptom"],
        "treatment": row["treatment"],
        "prevention": row["prevention"],
    }


def list_all() -> Dict[str, Any]:
    period = current_period()
    with read_conn() as conn:
        plants = [
            _plant_from_row(r)
            for r in conn.execute(
                "SELECT * FROM plants ORDER BY rowid"
            ).fetchall()
        ]
        user_ids = [
            r["plant_id"]
            for r in conn.execute(
                "SELECT plant_id FROM user_plants ORDER BY rowid"
            ).fetchall()
        ]
        todo_ids = [
            r["plant_id"]
            for r in conn.execute(
                "SELECT plant_id FROM todo_done WHERE period=? ORDER BY done_at",
                (period,),
            ).fetchall()
        ]
        diseases = [
            _disease_from_row(r)
            for r in conn.execute(
                "SELECT * FROM diseases ORDER BY name COLLATE NOCASE"
            ).fetchall()
        ]
    return {
        "plantList": plants,
        "userPlantIdList": user_ids,
        "todoDone": todo_ids,
        "todoPeriod": period,
        "diseases": diseases,
    }


def _plant_values(obj: Dict[str, Any]) -> Tuple[str, ...]:
    values = (
        _str(obj.get("area")).strip(),
        _str(obj.get("sowTime")).strip(),
        _str(obj.get("bloomTime")).strip(),
        _str(obj.get("desc")).strip(),
        _str(obj.get("care")).strip(),
        _str(obj.get("disease")).strip(),
        _str(obj.get("img")).strip(),
    )
    limits = (
        ("种植地区", 500),
        ("种植时间", 2_000),
        ("花期", 2_000),
        ("详细介绍", 20_000),
        ("养护方法", 20_000),
        ("常见病害", 20_000),
        ("图片数据", 12_000_000),
    )
    for (label, limit), value in zip(limits, values):
        if len(value) > limit:
            raise DataError(f"{label}内容过长（最多 {limit} 字符）", 413)
    return values


def save_plant(obj: Dict[str, Any], edit_source: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise DataError("请求数据格式错误")
    pid = _str(obj.get("id")).strip()
    name = _str(obj.get("name")).strip()
    if not name:
        raise DataError("植物名称不能为空")
    if len(name) > 100:
        raise DataError("植物名称过长（最多 100 字）")
    if edit_source not in ("user", "lib"):
        raise DataError("editSource 只能是 user 或 lib")
    values = _plant_values(obj)
    ts = now_iso()
    with transaction() as conn:
        created = False
        if pid:
            current = conn.execute(
                "SELECT name FROM plants WHERE id=?", (pid,)
            ).fetchone()
            if not current:
                raise DataError("植物不存在或已被删除", 404)
            # 仅当改名时才检查重名，允许历史重名条目在不改名的情况下正常编辑
            if name != current["name"]:
                dup = conn.execute(
                    "SELECT id FROM plants WHERE name=? AND id<>?", (name, pid)
                ).fetchone()
                if dup:
                    raise DataError(f"总库中已存在同名植物「{name}」", 409)
            conn.execute(
                """UPDATE plants SET name=?, area=?, sow_time=?, bloom_time=?,
                   description=?, care=?, disease=?, img=?, updated_at=? WHERE id=?""",
                (name, *values, ts, pid),
            )
        else:
            matches = conn.execute(
                "SELECT id FROM plants WHERE name=? ORDER BY rowid", (name,)
            ).fetchall()
            if len(matches) == 1:
                pid = matches[0]["id"]
                conn.execute(
                    """UPDATE plants SET name=?, area=?, sow_time=?, bloom_time=?,
                       description=?, care=?, disease=?, img=?, updated_at=? WHERE id=?""",
                    (name, *values, ts, pid),
                )
            elif len(matches) > 1:
                raise DataError(
                    f"总库中存在 {len(matches)} 个同名植物「{name}」，"
                    "请到总库视图直接编辑目标植物，或先改名后再新增",
                    409,
                )
            else:
                pid = _new_plant_id(conn)
                conn.execute(
                    """INSERT INTO plants
                       (id,name,area,sow_time,bloom_time,description,care,disease,img,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (pid, name, *values, ts, ts),
                )
                created = True

        if edit_source == "user":
            conn.execute(
                "INSERT OR IGNORE INTO user_plants(plant_id, created_at) VALUES (?,?)",
                (pid, ts),
            )
    return {"ok": True, "id": pid, "created": created}


def _new_plant_id(conn: sqlite3.Connection) -> str:
    while True:
        pid = "p" + secrets.token_hex(8)
        if not conn.execute("SELECT 1 FROM plants WHERE id=?", (pid,)).fetchone():
            return pid


def delete_user_plant(pid: str) -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM user_plants WHERE plant_id=?", (pid,))
        conn.execute("DELETE FROM todo_done WHERE plant_id=?", (pid,))


def delete_store_plant(pid: str) -> None:
    with transaction() as conn:
        # 显式清理，兼容未开启外键连接的场景
        conn.execute("DELETE FROM todo_done WHERE plant_id=?", (pid,))
        conn.execute("DELETE FROM user_plants WHERE plant_id=?", (pid,))
        conn.execute("DELETE FROM plants WHERE id=?", (pid,))


def toggle_todo(pid: str, period: Optional[str] = None) -> Dict[str, Any]:
    if not pid:
        raise DataError("缺少植物 ID")
    period = period or current_period()
    if len(period) != 7 or period[4] != "-":
        raise DataError("period 格式应为 YYYY-MM")
    with transaction() as conn:
        if not conn.execute("SELECT 1 FROM plants WHERE id=?", (pid,)).fetchone():
            raise DataError("植物不存在或已被删除", 404)
        row = conn.execute(
            "SELECT 1 FROM todo_done WHERE plant_id=? AND period=?", (pid, period)
        ).fetchone()
        if row:
            conn.execute(
                "DELETE FROM todo_done WHERE plant_id=? AND period=?", (pid, period)
            )
            return {"ok": True, "done": False, "period": period}
        conn.execute(
            "INSERT INTO todo_done(plant_id, period, done_at) VALUES (?,?,?)",
            (pid, period, now_iso()),
        )
        return {"ok": True, "done": True, "period": period}


# ---------------------------------------------------------------------------
# 病害库
# ---------------------------------------------------------------------------


def save_disease(obj: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise DataError("请求数据格式错误")
    did = _str(obj.get("id")).strip()
    name = _str(obj.get("name")).strip()
    if not name:
        raise DataError("病害名称不能为空")
    if len(name) > 100:
        raise DataError("病害名称过长（最多 100 字）")
    symptom = _str(obj.get("symptom")).strip()
    treatment = _str(obj.get("treatment")).strip()
    prevention = _str(obj.get("prevention")).strip()
    if len(symptom) > 20_000 or len(treatment) > 20_000 or len(prevention) > 20_000:
        raise DataError("病害内容过长（每项最多 20000 字符）", 413)
    ts = now_iso()
    with transaction() as conn:
        dup = conn.execute(
            "SELECT id FROM diseases WHERE name=? AND id<>?", (name, did or "")
        ).fetchone()
        if dup:
            raise DataError(f"病害库中已存在「{name}」", 409)
        if did:
            if not conn.execute(
                "SELECT 1 FROM diseases WHERE id=?", (did,)
            ).fetchone():
                raise DataError("病害记录不存在", 404)
            conn.execute(
                """UPDATE diseases SET name=?, symptom=?, treatment=?, prevention=?,
                   updated_at=? WHERE id=?""",
                (name, symptom, treatment, prevention, ts, did),
            )
        else:
            did = "d" + secrets.token_hex(8)
            conn.execute(
                """INSERT INTO diseases
                   (id,name,symptom,treatment,prevention,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (did, name, symptom, treatment, prevention, ts, ts),
            )
    return {"ok": True, "id": did}


def delete_disease(did: str) -> None:
    if not did:
        raise DataError("缺少病害 ID")
    with transaction() as conn:
        cur = conn.execute("DELETE FROM diseases WHERE id=?", (did,))
        if cur.rowcount == 0:
            raise DataError("病害记录不存在", 404)


# ---------------------------------------------------------------------------
# 导入 / 导出
# ---------------------------------------------------------------------------


def export_data() -> Dict[str, Any]:
    data = list_all()
    with read_conn() as conn:
        rows = conn.execute(
            "SELECT plant_id, period FROM todo_done ORDER BY period, done_at"
        ).fetchall()
    by_period: Dict[str, List[str]] = {}
    for r in rows:
        by_period.setdefault(r["period"], []).append(r["plant_id"])
    data["todoDoneByPeriod"] = by_period
    data["exportTime"] = now_iso()
    data["schemaVersion"] = SCHEMA_VERSION
    return data


def _validate_text_field(value: Any, field: str, max_len: int = 2_000_000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise DataError(f"字段 {field} 必须是字符串")
    if len(value) > max_len:
        raise DataError(f"字段 {field} 内容过大")
    return value


def _normalize_import(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise DataError("备份文件格式错误：根节点必须是对象")
    raw_plants = data.get("plantList")
    if not isinstance(raw_plants, list):
        raise DataError("备份文件格式错误：plantList 必须是数组")
    period = current_period()
    plants: List[Dict[str, str]] = []
    ids = set()
    for idx, p in enumerate(raw_plants):
        if not isinstance(p, dict):
            raise DataError(f"plantList[{idx}] 格式错误")
        pid = _validate_text_field(p.get("id"), "id", 200).strip()
        name = _validate_text_field(p.get("name"), "name", 200).strip()
        if not pid or not name:
            raise DataError(f"plantList[{idx}] 缺少 id 或 name")
        if pid in ids:
            raise DataError(f"plantList 中 id 重复：{pid}")
        ids.add(pid)
        plants.append(
            {
                "id": pid,
                "name": name,
                "area": _validate_text_field(p.get("area"), "area"),
                "sowTime": _validate_text_field(p.get("sowTime"), "sowTime"),
                "bloomTime": _validate_text_field(p.get("bloomTime"), "bloomTime"),
                "desc": _validate_text_field(p.get("desc"), "desc"),
                "care": _validate_text_field(p.get("care"), "care"),
                "disease": _validate_text_field(p.get("disease"), "disease"),
                "img": _validate_text_field(p.get("img"), "img", 16_000_000),
            }
        )

    raw_users = data.get("userPlantIdList", [])
    if not isinstance(raw_users, list):
        raise DataError("备份文件格式错误：userPlantIdList 必须是数组")
    user_ids = []
    for pid in raw_users:
        pid = _validate_text_field(pid, "userPlantIdList").strip()
        if pid in ids and pid not in user_ids:
            user_ids.append(pid)

    # 新格式优先；旧格式 todoDone 归属当前月份
    raw_by_period = data.get("todoDoneByPeriod")
    by_period: Dict[str, List[str]] = {}
    if isinstance(raw_by_period, dict):
        for per, plist in raw_by_period.items():
            if not isinstance(per, str) or len(per) != 7 or per[4] != "-":
                continue
            if not isinstance(plist, list):
                raise DataError("备份文件格式错误：todoDoneByPeriod 的值必须是数组")
            for pid in plist:
                pid = _validate_text_field(pid, "todoDoneByPeriod").strip()
                if pid in ids:
                    by_period.setdefault(per, []).append(pid)
    else:
        raw_todo = data.get("todoDone", [])
        if not isinstance(raw_todo, list):
            raise DataError("备份文件格式错误：todoDone 必须是数组")
        for pid in raw_todo:
            pid = _validate_text_field(pid, "todoDone").strip()
            if pid in ids:
                by_period.setdefault(period, []).append(pid)

    diseases = []
    raw_diseases = data.get("diseases", [])
    if not isinstance(raw_diseases, list):
        raise DataError("备份文件格式错误：diseases 必须是数组")
    disease_names = set()
    disease_ids = set()
    for idx, d in enumerate(raw_diseases):
        if not isinstance(d, dict):
            raise DataError(f"diseases[{idx}] 格式错误")
        name = _validate_text_field(d.get("name"), "disease.name", 200).strip()
        if not name:
            raise DataError(f"diseases[{idx}] 缺少 name")
        if name in disease_names:
            raise DataError(f"diseases 中名称重复：{name}")
        disease_names.add(name)
        did = _validate_text_field(d.get("id"), "disease.id", 200).strip()
        if did:
            if did in disease_ids:
                raise DataError(f"diseases 中 id 重复：{did}")
            disease_ids.add(did)
        diseases.append(
            {
                "id": did or ("d" + secrets.token_hex(8)),
                "name": name,
                "symptom": _validate_text_field(d.get("symptom"), "symptom"),
                "treatment": _validate_text_field(d.get("treatment"), "treatment"),
                "prevention": _validate_text_field(d.get("prevention"), "prevention"),
            }
        )

    return {
        "plants": plants,
        "user_ids": user_ids,
        "todo_by_period": by_period,
        "diseases": diseases,
    }


def import_data(data: Any) -> Dict[str, Any]:
    """整库覆盖导入：先校验，再在单个事务中替换，失败自动回滚。"""
    normalized = _normalize_import(data)
    backup = backup_database("before-import")
    ts = now_iso()
    with transaction() as conn:
        conn.execute("DELETE FROM todo_done")
        conn.execute("DELETE FROM user_plants")
        conn.execute("DELETE FROM plants")
        conn.execute("DELETE FROM diseases")
        for p in normalized["plants"]:
            conn.execute(
                """INSERT INTO plants
                   (id,name,area,sow_time,bloom_time,description,care,disease,img,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    p["id"],
                    p["name"],
                    p["area"],
                    p["sowTime"],
                    p["bloomTime"],
                    p["desc"],
                    p["care"],
                    p["disease"],
                    p["img"],
                    ts,
                    ts,
                ),
            )
        for pid in normalized["user_ids"]:
            conn.execute(
                "INSERT OR IGNORE INTO user_plants(plant_id, created_at) VALUES (?,?)",
                (pid, ts),
            )
        for period, pids in normalized["todo_by_period"].items():
            for pid in pids:
                conn.execute(
                    "INSERT OR IGNORE INTO todo_done(plant_id, period, done_at) VALUES (?,?,?)",
                    (pid, period, ts),
                )
        for d in normalized["diseases"]:
            conn.execute(
                """INSERT INTO diseases
                   (id,name,symptom,treatment,prevention,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    d["id"],
                    d["name"],
                    d["symptom"],
                    d["treatment"],
                    d["prevention"],
                    ts,
                    ts,
                ),
            )
    return {
        "ok": True,
        "plants": len(normalized["plants"]),
        "userPlants": len(normalized["user_ids"]),
        "diseases": len(normalized["diseases"]),
        "todoPeriods": len(normalized["todo_by_period"]),
        "backup": backup,
    }


def stats() -> Dict[str, Any]:
    with read_conn() as conn:
        return {
            "plants": conn.execute("SELECT COUNT(*) FROM plants").fetchone()[0],
            "userPlants": conn.execute("SELECT COUNT(*) FROM user_plants").fetchone()[0],
            "diseases": conn.execute("SELECT COUNT(*) FROM diseases").fetchone()[0],
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "sessions": conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
        }


# ---------------------------------------------------------------------------
# 应用设置（AI 接口配置）
# ---------------------------------------------------------------------------

AI_SETTING_KEYS = ("ai_api_key", "ai_base_url", "ai_model")


def get_app_settings(keys: Tuple[str, ...] = AI_SETTING_KEYS) -> Dict[str, str]:
    """读取 meta 中的设置项，未设置的键不会出现在结果里。"""
    result: Dict[str, str] = {}
    with read_conn() as conn:
        for key in keys:
            value = _meta_get(conn, key)
            if value is not None:
                result[key] = value
    return result


def save_app_settings(values: Dict[str, Optional[str]]) -> None:
    """写入设置；值为 None 时删除该键。"""
    with transaction() as conn:
        for key, value in values.items():
            if value is None:
                conn.execute("DELETE FROM meta WHERE key=?", (key,))
            else:
                _meta_set(conn, key, value)
