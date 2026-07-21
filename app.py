import os
import time
import secrets
import sqlite3
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect, session, url_for, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ============================================================
# Session 密钥
# ============================================================
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
)

# ============================================================
# Session Cookie 安全配置
# ============================================================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB 最大上传
)

# ============================================================
# 用户数据库（内存字典 — 用于登录认证）
# ============================================================
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def sanitize_user(user):
    """移除敏感字段，返回安全的用户信息"""
    if user is None:
        return None
    safe = dict(user)
    safe.pop("password", None)
    return safe


# ============================================================
# 登录限流
# ============================================================
login_attempts = defaultdict(list)
RATE_LIMIT_WINDOW = 60
MAX_ATTEMPTS = 5


def is_rate_limited(ip):
    now = time.time()
    login_attempts[ip] = [
        t for t in login_attempts[ip] if now - t < RATE_LIMIT_WINDOW
    ]
    return len(login_attempts[ip]) >= MAX_ATTEMPTS


def record_attempt(ip):
    login_attempts[ip].append(time.time())


# ============================================================
# CSRF Token
# ============================================================
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token):
    saved = session.get("_csrf_token")
    if not saved or not token:
        return False
    session.pop("_csrf_token", None)
    return secrets.compare_digest(saved, token)


# ============================================================
# SQLite 数据库初始化（故意使用明文密码）
# ============================================================
def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户 — 明文密码（SQL 注入训练需要）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    # 注意：上面故意少写了括号，补全
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[SQLite] 数据库初始化完成 - data/users.db")
    # 创建上传目录
    os.makedirs("static/uploads", exist_ok=True)


# ============================================================
# 路由：首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = sanitize_user(USERS[username])
    return render_template("index.html", user=user)


# ============================================================
# 路由：登录（保持原有逻辑不变）
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        csrf_token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_token):
            abort(403, description="CSRF 验证失败，请刷新页面重试。")

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        client_ip = request.remote_addr or "unknown"
        if is_rate_limited(client_ip):
            error = "登录尝试次数过多，请 60 秒后重试。"
            return render_template(
                "login.html",
                error=error,
                csrf_token=generate_csrf_token(),
            )

        record_attempt(client_ip)

        user = USERS.get(username)
        if user is None:
            check_password_hash("$2b$12$dummy.salt.dummy.hash", password)
            error = "用户名或密码错误"
        elif check_password_hash(user["password"], password):
            session["username"] = username
            return redirect(url_for("index"))
        else:
            error = "用户名或密码错误"

    return render_template(
        "login.html",
        error=error,
        csrf_token=generate_csrf_token(),
    )


# ============================================================
# 路由：注册（SQL 注入漏洞 — f-string 拼接）
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] 注册查询: {query} 参数: username={username}")

        try:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            c.execute(query, (username, password, email, phone))
            conn.commit()
            conn.close()
            success = "注册成功，请登录"
            return render_template("register.html", success=success)
        except Exception as e:
            error = f"注册失败: {str(e)}"

    return render_template("register.html", error=error)


# ============================================================
# 路由：搜索（SQL 注入漏洞 — f-string 拼接）
# ============================================================
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "")

    if not keyword:
        return redirect(url_for("index"))

    keyword_param = f"%{keyword}%"
    query = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
    print(f"[SQL] 搜索查询: {query} 参数: keyword={keyword}")

    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute(query, (keyword_param, keyword_param))
        results = c.fetchall()
        conn.close()
        print(f"[SQL] 搜索结果: {len(results)} 行")
    except Exception as e:
        results = []
        print(f"[SQL] 搜索错误: {str(e)}")

    # 将搜索结果传入首页模板
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = sanitize_user(USERS[username])

    return render_template("index.html", user=user, search_results=results, search_keyword=keyword)


# ============================================================
# 路由：上传头像（无文件类型检查漏洞）
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    error = None
    success = None
    filename = None

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            filename = file.filename
            try:
                file.save(os.path.join("static/uploads", filename))
                success = "上传成功"
            except Exception as e:
                error = f"上传失败: {str(e)}"
        else:
            error = "请选择要上传的文件"

    return render_template("upload.html", error=error, success=success, filename=filename)


# ============================================================
# 路由：退出
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
