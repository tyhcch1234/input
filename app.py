"""
登入示範網站 —— Flask + SQLite
--------------------------------
功能：
  1. 註冊 / 登入 / 登出（密碼經 scrypt 加鹽雜湊後儲存，絕不存明文）
  2. Session 驗證 + 受保護頁面（未登入自動跳到登入頁）
  3. SQLite 資料庫：users 表 + notes 表（每人只能看到自己的筆記）
  4. 筆記 CRUD：新增 / 刪除，示範真正的資料庫讀寫
  5. 修改密碼、記住登入時間

啟動：python app.py   然後開 http://127.0.0.1:5000
"""

import os
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, flash, g, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

app = Flask(__name__)

# SECRET_KEY 用於簽署 session cookie。正式上線請改由環境變數提供。
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS 讀不到 cookie，防 XSS 偷 session
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # 防 CSRF
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)


# --------------------------------------------------------------------------
# 資料庫：每個 request 開一條連線，request 結束自動關閉
# --------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """建立資料表（若不存在）。第一次啟動時自動執行。"""
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL,
                last_login    TEXT
            );

            CREATE TABLE IF NOT EXISTS notes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                title      TEXT    NOT NULL,
                body       TEXT    NOT NULL DEFAULT '',
                created_at TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_notes_user ON notes (user_id);
            """
        )


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# 驗證工具
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username, email, password, password2):
    """回傳錯誤訊息，通過驗證則回傳 None。"""
    if not 3 <= len(username) <= 20:
        return "用戶名稱長度需為 3–20 個字元。"
    if not re.fullmatch(r"[A-Za-z0-9_.]+", username):
        return "用戶名稱只可包含英文字母、數字、底線與點。"
    if not EMAIL_RE.match(email):
        return "電郵格式不正確。"
    if len(password) < 8:
        return "密碼至少需要 8 個字元。"
    if password != password2:
        return "兩次輸入的密碼不一致。"
    return None


def login_required(view):
    """裝飾器：未登入者一律導向登入頁。"""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("請先登入才能進入該頁面。", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_user():
    """把目前登入者載入 g.user，方便模板使用。"""
    uid = session.get("user_id")
    g.user = None
    if uid:
        g.user = get_db().execute(
            "SELECT id, username, email, created_at, last_login FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if g.user is None:      # 帳號已被刪除 → 清掉 session
            session.clear()


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


# --------------------------------------------------------------------------
# 路由：公開頁面
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        error = validate_registration(username, email, password, password2)
        if error:
            flash(error, "error")
            return render_template("register.html", username=username, email=email)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, generate_password_hash(password), now_str()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # UNIQUE 約束觸發 —— 真正由資料庫把關，不只靠前端檢查
            flash("此用戶名稱或電郵已被註冊。", "error")
            return render_template("register.html", username=username, email=email)

        flash("註冊成功，請登入。", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()   # 用戶名或電郵
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        row = get_db().execute(
            "SELECT * FROM users WHERE lower(username) = ? OR email = ?",
            (identity, identity),
        ).fetchone()

        # 帳號不存在與密碼錯誤回傳同一訊息，避免洩漏哪些帳號存在
        if row is None or not check_password_hash(row["password_hash"], password):
            flash("帳號或密碼不正確。", "error")
            return render_template("login.html", identity=identity)

        db = get_db()
        db.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str(), row["id"]))
        db.commit()

        session.clear()
        session["user_id"] = row["id"]
        session.permanent = remember       # 勾選「記住我」→ cookie 存活 7 天
        flash(f"歡迎回來，{row['username']}！", "success")
        return redirect(request.args.get("next") or url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("已成功登出。", "success")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------
# 路由：需登入
# --------------------------------------------------------------------------
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    db = get_db()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title:
            flash("筆記標題不可留空。", "error")
        else:
            db.execute(
                "INSERT INTO notes (user_id, title, body, created_at) VALUES (?, ?, ?, ?)",
                (g.user["id"], title[:120], body, now_str()),
            )
            db.commit()
            flash("筆記已新增。", "success")
        return redirect(url_for("dashboard"))

    notes = db.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC",
        (g.user["id"],),
    ).fetchall()

    stats = db.execute(
        "SELECT COUNT(*) AS total, MAX(created_at) AS latest FROM notes WHERE user_id = ?",
        (g.user["id"],),
    ).fetchone()

    return render_template("dashboard.html", notes=notes, stats=stats)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db = get_db()
    # WHERE 同時比對 user_id → 無法刪除別人的筆記
    cursor = db.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, g.user["id"]),
    )
    db.commit()
    if cursor.rowcount:
        flash("筆記已刪除。", "success")
    else:
        flash("找不到該筆記，或不屬於你。", "error")
    return redirect(url_for("dashboard"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        db = get_db()
        row = db.execute(
            "SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)
        ).fetchone()

        if not check_password_hash(row["password_hash"], current):
            flash("目前的密碼不正確。", "error")
        elif len(new) < 8:
            flash("新密碼至少需要 8 個字元。", "error")
        elif new != confirm:
            flash("兩次輸入的新密碼不一致。", "error")
        elif new == current:
            flash("新密碼不可與目前密碼相同。", "error")
        else:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new), g.user["id"]),
            )
            db.commit()
            flash("密碼已更新，請重新登入。", "success")
            session.clear()
            return redirect(url_for("login"))

    return render_template("change_password.html")


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="找不到這個頁面。"), 404


if __name__ == "__main__":
    init_db()
    print(f"資料庫位置：{DB_PATH}")
    print("開啟 http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
