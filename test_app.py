"""端到端煙霧測試：用 Flask test client 走一次完整流程。"""
import os
import sqlite3
import tempfile

import app as appmod

# 用臨時資料庫，避免污染 app.db
tmp = tempfile.mkdtemp()
appmod.DB_PATH = os.path.join(tmp, "test.db")
appmod.app.config.update(TESTING=True, SECRET_KEY="test-key")
appmod.init_db()

c = appmod.app.test_client()
checks = []


def check(name, cond):
    checks.append((name, bool(cond)))
    print(("  PASS  " if cond else "  FAIL  ") + name)


# 1. 未登入訪問受保護頁 → 應被導向 /login
r = c.get("/dashboard", follow_redirects=False)
check("未登入訪問 /dashboard 被導向登入頁", r.status_code == 302 and "/login" in r.headers["Location"])

# 2. 密碼太短 → 應被拒
r = c.post("/register", data={"username": "alice", "email": "a@example.com", "password": "123", "password2": "123"}, follow_redirects=True)
with sqlite3.connect(appmod.DB_PATH) as db:
    n = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
check("弱密碼註冊被拒絕（資料庫無新增）", n == 0 and "8 個字元".encode() in r.data)

# 3. 兩次密碼不一致 → 應被拒
r = c.post("/register", data={"username": "alice", "email": "a@example.com", "password": "password123", "password2": "password999"}, follow_redirects=True)
check("兩次密碼不一致被拒絕", "不一致".encode() in r.data)

# 4. 正常註冊
r = c.post("/register", data={"username": "alice", "email": "alice@example.com", "password": "password123", "password2": "password123"}, follow_redirects=True)
with sqlite3.connect(appmod.DB_PATH) as db:
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM users WHERE username='alice'").fetchone()
check("註冊成功且資料寫入 users 表", row is not None)
check("密碼未以明文儲存", row is not None and "password123" not in row["password_hash"])
h = row["password_hash"] if row is not None else ""
check("密碼雜湊格式正確（scrypt 加鹽）", h.startswith("scrypt:") and h.count("$") == 2)

# 5. 重複註冊（電郵相同、大小寫不同）→ UNIQUE 約束攔截
r = c.post("/register", data={"username": "alice2", "email": "ALICE@example.com", "password": "password123", "password2": "password123"}, follow_redirects=True)
with sqlite3.connect(appmod.DB_PATH) as db:
    n = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
check("重複電郵被 UNIQUE 約束攔截", n == 1)

# 6. 錯誤密碼登入 → 失敗
r = c.post("/login", data={"identity": "alice", "password": "wrongpass"}, follow_redirects=True)
check("錯誤密碼無法登入", "不正確".encode() in r.data)

# 7. 不存在的帳號 → 同一錯誤訊息（不洩漏帳號是否存在）
r = c.post("/login", data={"identity": "nobody", "password": "whatever"}, follow_redirects=True)
check("不存在帳號回傳相同錯誤訊息", "不正確".encode() in r.data and r.status_code == 200)

# 8. 正確登入
r = c.post("/login", data={"identity": "alice@example.com", "password": "password123"}, follow_redirects=True)
check("以電郵登入成功並進入儀表板", "我的筆記".encode() in r.data)
with sqlite3.connect(appmod.DB_PATH) as db:
    last = db.execute("SELECT last_login FROM users WHERE username='alice'").fetchone()[0]
check("登入時間已寫入資料庫", last is not None)

# 9. 新增筆記
r = c.post("/dashboard", data={"title": "第一則筆記", "body": "內容測試"}, follow_redirects=True)
with sqlite3.connect(appmod.DB_PATH) as db:
    note = db.execute("SELECT * FROM notes").fetchone()
check("筆記已寫入 notes 表", note is not None and note[2] == "第一則筆記")
check("筆記頁面顯示新筆記", "第一則筆記".encode() in r.data)

note_id = note[0]
owner_id = row["id"]

# 10. 另一個用戶不能刪除 alice 的筆記
c2 = appmod.app.test_client()
c2.post("/register", data={"username": "bob", "email": "bob@example.com", "password": "password123", "password2": "password123"})
c2.post("/login", data={"identity": "bob", "password": "password123"})
c2.post(f"/notes/{note_id}/delete")
with sqlite3.connect(appmod.DB_PATH) as db:
    still = db.execute("SELECT COUNT(*) FROM notes WHERE id=?", (note_id,)).fetchone()[0]
check("他人無法刪除不屬於自己的筆記", still == 1)

# 11. bob 的儀表板看不到 alice 的筆記
r = c2.get("/dashboard")
check("用戶之間筆記互相隔離", "第一則筆記".encode() not in r.data)

# 12. 本人刪除筆記
c.post(f"/notes/{note_id}/delete")
with sqlite3.connect(appmod.DB_PATH) as db:
    gone = db.execute("SELECT COUNT(*) FROM notes WHERE id=?", (note_id,)).fetchone()[0]
check("本人可以刪除自己的筆記", gone == 0)

# 13. 修改密碼：目前密碼錯誤 → 失敗
r = c.post("/change-password", data={"current_password": "bad", "new_password": "newpassword123", "confirm_password": "newpassword123"}, follow_redirects=True)
check("目前密碼錯誤時無法改密碼", "不正確".encode() in r.data)

# 14. 修改密碼成功 → 舊密碼失效、新密碼可用
c.post("/change-password", data={"current_password": "password123", "new_password": "newpassword123", "confirm_password": "newpassword123"})
r_old = c.post("/login", data={"identity": "alice", "password": "password123"}, follow_redirects=True)
r_new = c.post("/login", data={"identity": "alice", "password": "newpassword123"}, follow_redirects=True)
check("改密碼後舊密碼失效", "不正確".encode() in r_old.data)
check("改密碼後新密碼可登入", "我的筆記".encode() in r_new.data)

# 15. 登出後不能再進入受保護頁
c.get("/logout")
r = c.get("/dashboard", follow_redirects=False)
check("登出後受保護頁再次被攔截", r.status_code == 302 and "/login" in r.headers["Location"])

# 16. SQL 注入嘗試：以注入字串登入
r = c.post("/login", data={"identity": "alice' OR '1'='1", "password": "x' OR '1'='1"}, follow_redirects=True)
check("SQL 注入嘗試無法登入", "我的筆記".encode() not in r.data)

# 17. 404 頁面
r = c.get("/no-such-page")
check("404 頁面正常回應", r.status_code == 404)

passed = sum(1 for _, ok in checks if ok)
print(f"\n結果：{passed}/{len(checks)} 項通過")
raise SystemExit(0 if passed == len(checks) else 1)
