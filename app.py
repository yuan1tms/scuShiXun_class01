import os
import time
import uuid
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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 添加 balance 列（兼容旧数据库）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在
    # 插入默认用户 — 明文密码（SQL 注入训练需要）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()
    print("[SQLite] 数据库初始化完成 - data/users.db")
    # 创建上传目录
    os.makedirs("static/uploads", exist_ok=True)
    # 创建 pages 目录
    os.makedirs("pages", exist_ok=True)


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
# 路由：上传头像
# ============================================================
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}


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
            original = file.filename
            # 获取文件扩展名（小写）
            ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""

            # 检查扩展名是否在允许列表中
            if ext not in ALLOWED_EXTENSIONS:
                error = f"不支持的文件类型 (.{ext})，仅支持图片格式"
            else:
                # 生成唯一文件名防止覆盖
                unique_name = f"{uuid.uuid4().hex}.{ext}"
                save_path = os.path.join("static/uploads", unique_name)
                try:
                    file.save(save_path)
                    success = "上传成功"
                    filename = unique_name
                except Exception as e:
                    error = f"上传失败: {str(e)}"
        else:
            error = "请选择要上传的文件"

    return render_template("upload.html", error=error, success=success, filename=filename)


# ============================================================
# 路由：个人中心（仅查看自己的资料）
# ============================================================
@app.route("/profile", methods=["GET"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    profile_data = None
    error = None

    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        query = "SELECT id, username, email, phone, balance FROM users WHERE username = ?"
        print(f"[SQL] 查询个人资料: {query} 参数: username={session['username']}")
        c.execute(query, (session["username"],))
        row = c.fetchone()
        conn.close()
        if row:
            profile_data = {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "phone": row[3],
                "balance": row[4],
            }
        else:
            error = "用户不存在"
    except Exception as e:
        error = f"查询失败: {str(e)}"

    return render_template("profile.html", profile=profile_data, error=error,
                           csrf_token=generate_csrf_token())


# ============================================================
# 路由：充值（仅限给自己充值，有金额校验 + CSRF）
# ============================================================
@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    # CSRF 校验
    csrf_token = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_token):
        abort(403, description="CSRF 验证失败，请刷新页面重试。")

    user_id = request.form.get("user_id", "")
    amount_str = request.form.get("amount", "0")

    try:
        amount = float(amount_str)
    except ValueError:
        amount = 0

    # 校验：金额必须为正数且不超过上限
    if amount <= 0:
        return redirect("/profile?error=金额必须大于零")
    if amount > 100000:
        return redirect("/profile?error=单次充值金额不得超过 100,000 元")

    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 先查询 user_id 是否属于当前登录用户
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row or row[0] != session["username"]:
            conn.close()
            return redirect("/profile?error=无权操作该账户")

        query = "UPDATE users SET balance = balance + ? WHERE id = ?"
        print(f"[SQL] 充值查询: {query} 参数: amount={amount}, user_id={user_id}")
        c.execute(query, (amount, user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SQL] 充值错误: {str(e)}")

    return redirect("/profile")


# ============================================================
# 路由：退出
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ============================================================
# 路由：动态页面加载（路径遍历漏洞 — 直接拼接）
# ============================================================
# 路由：动态页面加载
# ============================================================
@app.route("/page", methods=["GET"])
def dynamic_page():
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_content="请指定页面名称（?name=页面名）")

    page_content = None

    # 安全检查：移除路径遍历字符
    name = name.replace("..", "").replace("/", "").replace("\\", "")
    # 只允许 .html 文件
    if not name.endswith(".html"):
        name = name + ".html"
    # 限制只读取 pages/ 目录下的文件
    safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
    if not safe_name:
        page_content = "文件名不合法"
    else:
        filepath = os.path.join("pages", safe_name)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            page_content = "页面不存在"

    username = session.get("username")
    user = None
    if username and username in USERS:
        user = sanitize_user(USERS[username])

    return render_template("index.html", user=user, page_content=page_content,
                           search_keyword="", search_results=[])


# ============================================================
# 路由：修改密码（无 CSRF、无原密码验证、可修改任意用户密码）
# ============================================================
@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")

    if not username or not new_password:
        return redirect("/profile?error=用户名和密码不能为空")

    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        query = "UPDATE users SET password = ? WHERE username = ?"
        print(f"[SQL] 修改密码: username={username}")
        c.execute(query, (new_password, username))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SQL] 修改密码错误: {str(e)}")

    return redirect("/profile")


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
