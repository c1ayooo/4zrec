# 用友U8CloudTaskTreeQuery存在SQL注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`

**请求体 / payload**
```
访问出现如下页面表示可能存在SQL注入漏洞
/service/~iufo/nc.itf.iufo.mobilereport.task.TaskTreeQuery?usercode=211

sqlmap
```

**其他**
- 用友U8 Cloud TaskTreeQuery存在SQL注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud