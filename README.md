# 登入示範網站（Flask + SQLite）

一個可直接執行的完整示範：**註冊 → 登入 → 受保護頁面 → 資料庫讀寫**。

## 快速開始

```bash
cd login_demo
pip install -r requirements.txt      # 只需 Flask
python app.py
```

開啟 <http://127.0.0.1:5000>，先按「立即註冊」建立帳號，再登入即可。

資料庫 `app.db` 會在第一次啟動時自動建立，內含兩張表：`users`、`notes`。

## 專案結構

```
login_demo/
├── app.py                  # 全部後端邏輯（路由、驗證、SQL）
├── requirements.txt
├── templates/
│   ├── base.html           # 版面 + 提示訊息
│   ├── index.html          # 首頁
│   ├── register.html       # 註冊表單
│   ├── login.html          # 登入表單
│   ├── dashboard.html      # 受保護頁：我的筆記（CRUD）
│   ├── change_password.html
│   └── error.html
└── static/style.css
```

## 功能

| 功能 | 說明 |
|---|---|
| 註冊 | 用戶名稱 / 電郵 / 密碼，前後端雙重驗證，資料庫 UNIQUE 約束防重複 |
| 登入 | 可用用戶名稱或電郵；勾「記住我」延長 session 至 7 天 |
| 登出 | 清空 session |
| 受保護頁面 | `@login_required` 裝飾器，未登入自動轉到登入頁並記住原網址 |
| 筆記 CRUD | 新增、刪除（刪除時同時比對 `user_id`，無法操作他人資料） |
| 修改密碼 | 需輸入目前密碼，成功後強制重新登入 |

## 資料表

```sql
users (id, username UNIQUE, email UNIQUE, password_hash, created_at, last_login)

notes (id, user_id → users.id, title, body, created_at)
```

## 安全設計

- 密碼以 **scrypt + 隨機 salt**（werkzeug 3.x 預設）雜湊後才寫入資料庫，資料庫中不存在明文密碼。
- 所有 SQL 使用 **參數綁定**（`?` 佔位符），不會被字串拼接式注入攻擊。
- Session cookie 設 **HttpOnly + SameSite=Lax**，由 Flask 以 `SECRET_KEY` 簽署。
- 登入失敗時，帳號不存在與密碼錯誤回傳**同一個訊息**，不洩漏帳號是否存在。
- 資料查詢一律附帶 `user_id` 條件，做到水平權限隔離。

## 正式上線前必須改的地方

1. `SECRET_KEY` 改由環境變數提供，勿用預設值：
   `export SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")`
2. 關閉 `debug=True`，改用 Gunicorn / uWSGI 等 WSGI 伺服器。
3. 加上 HTTPS，並把 `SESSION_COOKIE_SECURE` 設為 `True`。
4. SQLite 換成 PostgreSQL / MySQL（並發寫入與備份更可靠）。
5. 補上登入失敗次數限制、電郵驗證、密碼重設流程。

## 查看資料庫內容

```bash
sqlite3 app.db "SELECT id, username, email, substr(password_hash,1,40)||'...' AS hash FROM users;"
sqlite3 app.db "SELECT id, user_id, title FROM notes;"
```
