# 🔴 SQL 注入漏洞修复报告 — SQL Injection Fix Report

| 项目 | 信息 |
|------|------|
| **项目名称** | Flask User Management System |
| **漏洞类型** | SQL Injection（SQL 注入） |
| **修复日期** | 2026-07-20 |
| **报告人** | yuan1tms |
| **漏洞数量** | **2 (All Fixed ✅)** |

---

## 一、漏洞概述 / Vulnerability Overview

本次审计发现项目存在 **2 个 SQL 注入漏洞**，均位于数据库操作层。攻击者可通过搜索和注册功能注入恶意 SQL 语句，实现**任意数据查询和提取**。

| 编号 | 漏洞名称 | 风险等级 | 修复状态 |
|:----:|----------|:--------:|:--------:|
| SQL-01 | Search SQL Injection（搜索功能 SQL 注入） | 🔴 **CRITICAL** | ✅ Fixed |
| SQL-02 | Register SQL Injection（注册功能 SQL 注入） | 🔴 **CRITICAL** | ✅ Fixed |

---

## 二、漏洞详情与修复方案 / Detailed Fix Report

---

### 🔴 SQL-01：搜索功能 SQL 注入

**漏洞位置：** `app.py` → `search()` 路由

**风险描述：**
搜索功能将用户输入的 `keyword` 通过 **f-string** 直接拼接到 SQL 查询语句中。攻击者可在 keyword 参数中注入 UNION、OR 等 SQL 关键字，实现任意数据查询。对应 **OWASP Top 10 A03: Injection**。

**攻击验证（修复前）：**

| 攻击手法 | 输入 Payload | 结果 |
|:--------:|-------------|:----:|
| UNION 注入 | `' UNION SELECT 1,username\|\|'~'\|\|password,3,email,phone FROM users--` | ❌ 成功提取所有用户名和密码 |
| OR 万能条件 | `' OR '1'='1` | ❌ 成功返回数据库全部用户 |

**漏洞代码（修复前）：**
```python
# ❌ f-string 直接拼接
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(query)
```

**修复代码（参数化查询）：**
```python
# ✅ 参数化查询
keyword_param = f"%{keyword}%"
query = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(query, (keyword_param, keyword_param))
```

**修复原理：**
参数化查询将用户输入与 SQL 语句**彻底分离**。数据库引擎收到的是已编译的 SQL 模板（`?` 占位符）和纯数据参数两部分。用户输入中的任何 SQL 关键字（`UNION`、`OR`、`--`）都**被视为普通字符串值**，永不参与 SQL 语法解析。

```sql
-- 修复前（可注入）
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%'
--                             用户输入变成SQL代码 ↑↑↑↑↑↑↑↑

-- 修复后（不可注入）
SELECT * FROM users WHERE username LIKE ?  -- 参数: "' OR '1'='1"
--                             输入仅作为字符串值传入 ↑↑↑↑↑↑↑↑↑↑↑↑
```

---

### 🔴 SQL-02：注册功能 SQL 注入

**漏洞位置：** `app.py` → `register()` 路由

**风险描述：**
注册功能将用户名、密码、邮箱、手机号四个字段全部通过 f-string 拼接到 INSERT 语句中。攻击者可在用户名中嵌入 SQL 语句，实现任意数据插入或利用堆叠查询执行其他操作。

**漏洞代码（修复前）：**
```python
# ❌ 四个字段全部拼接
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(query)
```

**修复代码（参数化查询）：**
```python
# ✅ 参数化查询
query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(query, (username, password, email, phone))
```

**修复验证：**
即使输入 `test'or'1'='1` 或 `hacker'),('1','2','3','4')--` 等恶意用户名，也能安全地存储为合法数据，不会影响 SQL 语法结构。

---

## 三、修复前后对比 / Before vs After

### 3.1 SQL 语句对比

| 功能 | 修复前（拼接） | 修复后（参数化） |
|:----:|:------------:|:--------------:|
| **搜索** | `LIKE '%{keyword}%'` ❌ | `LIKE ?` ✅ |
| **注册** | `VALUES ('{user}', ...)` ❌ | `VALUES (?, ?, ?, ?)` ✅ |

### 3.2 攻击效果对比

| 攻击手法 | 修复前 | 修复后 |
|:--------:|:------:|:------:|
| **UNION SELECT 数据提取** | ❌ 获取所有用户密码 | ✅ 注入无效（视为字符串） |
| **OR '1'='1 万能条件** | ❌ 返回全部用户数据 | ✅ 返回 0 条（注入无效） |

### 3.3 代码变更量

```
app.py: 4 行修改
  ├── register() 路由: 修改 2 行 (query + execute)
  └── search() 路由:  修改 2 行 (query + execute)
其他文件: 无修改
```

---

## 四、修复成果总结 / Summary

### 4.1 修复统计

| 指标 / Metric | 数值 / Value |
|:--------------|:------------:|
| 修复漏洞总数 | **2** (CRITICAL ×2) |
| 代码修改位置 | 2 处（search + register） |
| 修改行数 | 4 行 |
| 涉及数据库操作 | **100%**（全部使用参数化查询） |
| 可复现攻击路径 | **0**（全部阻断） |

### 4.2 攻击路径对比

```
❌ 修复前:
  搜索框输入恶意 SQL → f-string 拼接到 SQL 语句
  → UNION SELECT 提取全部密码
  → admin123 / alice2025 全部泄露
  → 可横向攻击其他系统

✅ 修复后:
  搜索框输入恶意 SQL → 参数化查询，不拼接
  → 注入语句被当作普通字符串
  → 返回 0 条结果
  → 攻击完全失败 🚫
```

### 4.3 防御架构

| 防护层级 | 具体措施 |
|----------|----------|
| 🛡️ **SQL 查询层** | 参数化查询（Prepared Statement） — `?` 占位符替代 f-string |
| ✅ **全量覆盖验证** | 全部 5 处 `c.execute()` 均使用参数化（init_db ×3 + register + search） |

---

## 五、防御建议 / Defense Recommendations

### 1️⃣ 始终使用参数化查询
所有数据库操作都应使用 `?` 占位符 + 参数元组的方式，**永远不要**使用字符串拼接或格式化构造 SQL。

### 2️⃣ 最小权限原则
数据库连接应使用仅具备必要权限的账号（如仅有 INSERT + SELECT + UPDATE 权限），避免使用管理员账号。

### 3️⃣ 输入验证（深度防御）
在参数化查询的基础上，对输入进行类型校验（如 id 必须是数字），提供第二层防护。

### 4️⃣ 错误信息不泄露
数据库错误信息不应直接返回给前端，避免攻击者通过报错信息推断数据库结构。

### 5️⃣ 定期安全审计
使用 sqlmap 等自动化工具定期扫描，检查是否存在遗漏的注入点。

```bash
# sqlmap 自动化检测示例
sqlmap -u "http://target/search?keyword=test" --cookie="session=xxx"
```

---

> **报告结束 · End of Report**
>
> 以上所有修复已在生产环境部署，已验证通过。
