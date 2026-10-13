# 成果自动检测 + 失败分类与策略切换

## 2C. 成果自动检测（Flag & Loot Detection）

> 在渗透过程中自动识别已获取的成果，避免遗漏关键发现。

### 检测模式库

```
CTF Flag 模式:
  HTB{...}          → HackTheBox
  THM{...}          → TryHackMe
  flag{...}         → 通用 CTF
  FLAG{...}         → 通用 CTF
  CTF{...}          → 通用 CTF
  [a-f0-9]{32}      → MD5 hash 格式 flag

凭据发现模式:
  password=xxx / passwd:xxx / pwd:xxx    → 明文密码
  $2y$..., $6$..., $1$...               → Hash（bcrypt/sha512/md5crypt）
  API-Key: xxx / Authorization: Bearer  → API 凭据
  aws_access_key_id / aws_secret        → 云凭据

敏感文件读取模式:
  root:x:0:0:                           → /etc/passwd 成功读取
  root:$6$...                           → /etc/shadow 成功读取
  DB_PASSWORD= / DB_HOST=               → .env 文件泄露
  define('DB_PASSWORD',                  → wp-config.php 泄露

Shell 获取模式:
  uid=33(www-data)                       → 低权限 shell
  uid=0(root)                            → root shell
  NT AUTHORITY\SYSTEM                    → Windows SYSTEM
  whoami 返回 + 命令执行确认             → RCE 确认

数据库访问模式:
  INSERT INTO / CREATE TABLE             → 数据库 dump 成功
  | column_name |                        → 表数据读取成功
  +----+--------+                        → MySQL 格式输出
```

### 发现后行动

```
发现凭据 → 立即尝试:
  1. SSH/RDP 登录（凭据复用）
  2. Web 管理面板登录
  3. 数据库直连
  4. 其他服务认证

发现 Shell → 立即执行:
  1. whoami && id && hostname
  2. uname -a (Linux) / systeminfo (Windows)
  3. 稳定化 shell（python -c 'import pty;pty.spawn("/bin/bash")'）
  4. 进入 PRIVESC 阶段

发现敏感文件 → 立即记录:
  1. 提取所有凭据/密钥
  2. 分析配置（内网地址、服务依赖）
  3. 评估是否可链式利用
```

---

---

## 2D. 失败分类与策略切换

> 遇阻时不盲目重试，根据失败类型切换对应策略。

### 失败分类矩阵

| 失败类型 | 识别特征 | 对应策略 |
|---------|---------|---------|
| **WAF_BLOCKED** | 403/406/429 + WAF 标头（Cloudflare/ModSecurity/AWS WAF） | 识别 WAF 类型 → 查对应 bypass 知识 → 编码变异/分块传输/HTTP2 走私 |
| **AUTH_REQUIRED** | 401/302 到登录页 | 尝试注册账号 → 默认凭据 → 登录后测试越权/IDOR |
| **RATE_LIMITED** | 429 Too Many Requests / 响应延迟递增 | 降速 → IP 轮转 → X-Forwarded-For 变异 → 分布式请求 |
| **INPUT_FILTERED** | 输入被清洗/转义/截断 | 分析过滤规则 → 双重编码 → 大小写变异 → 字符集替换 → 上下文切换 |
| **NOT_FOUND** | 404 / 空响应 | 换字典 → 扩展后缀 → 递归子目录 → 历史快照(wayback) |
| **TIMEOUT** | 连接超时 / 无响应 | 减小 payload → 尝试 OOB 技术 → DNS log 验证 → 切换协议 |
| **VERSION_PATCHED** | 已知 CVE 无法触发 | 确认版本是否精确 → 搜索相近版本漏洞 → 尝试变体利用 |
| **SANDBOX/JAIL** | 命令执行受限 / 函数禁用 | 枚举可用函数 → 替代执行路径 → 沙箱逃逸技术 |

### 策略切换决策流

```
失败 → 分类判断:

WAF_BLOCKED:
  1. 识别 WAF 类型（响应头 / 错误页面特征）
  2. 查询对应 WAF bypass 知识库
  3. 尝试: 编码变异 → 注释插入 → 大小写 → Unicode → 分块传输
  4. 仍失败: 切换攻击面（换其他端点/参数）

AUTH_REQUIRED:
  1. 检查是否可注册（优先注册进入系统）
  2. 尝试默认凭据（admin:admin, test:test, 等）
  3. 检查是否有密码重置功能（可能有逻辑漏洞）
  4. 注册后重新评估：测试越权、IDOR、功能级漏洞

RATE_LIMITED:
  1. 降低请求频率（3-5秒间隔）
  2. Header 变异: X-Forwarded-For / X-Real-IP / X-Originating-IP 随机化
  3. 切换到手工精准测试（减少无效请求）

INPUT_FILTERED:
  1. 确认过滤位置（输入时/输出时/存储时）
  2. 测试过滤边界（哪些字符被过滤/替换/截断）
  3. 使用对应绕过技术（双重编码/Unicode/HTML 实体/十六进制）
  4. 切换上下文注入（如从参数值切换到参数名/Header/Cookie）

NOT_FOUND:
  1. 扩展字典（raft-large / common + 技术栈专用字典）
  2. 尝试不同后缀（.php/.asp/.jsp/.bak/.old/.txt/.json）
  3. 递归扫描已发现目录的子目录
  4. 查历史快照: waybackurls / web.archive.org

连续 5 次同类失败 → 切换整个攻击方向:
  "这个入口可能确实不可利用，切换到其他服务/端口/子域"
```

---
