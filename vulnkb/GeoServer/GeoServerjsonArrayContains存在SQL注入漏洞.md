# GeoServerjsonArrayContains存在SQL注入漏洞

- **系统**：GeoServer　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="GeoServer"`
- **请求**：`GET /geoserver/ows?service=WFS&version=2.0.0&request=GetCapabilities HTTP/1.1`
- **关键头**：`id: geoserver-jsonarraycontains-sqli`　`name: GeoServer jsonArrayContains SQL 注入检测`　`author: mhtsec`　`severity: high`

**请求体 / payload**
```
GeoTools 在 GEOT-7589 为 PostgreSQL 12+ 引入 jsonb_path_exists 优化后，
jsonArrayContains 的第三个参数会未经 JSONPath/SQL 转义直接拼进 SQL。
本模板只验证堆叠语句是否到达 PostGIS：在 WFS 2.0 GetFeature 的 CQL_FILTER
中注入无副作用的 SELECT 1，若 pgJDBC 返回 Multiple ResultSets were returned，
即可确认存在 SQL 注入。不执行 COPY ... TO PROGRAM，也不验证操作系统命令执行。
前提：匿名可访问 WFS、图层走 PostGIS、PostgreSQL >= 12、存在可承载 JSON/NULL 的属性。
静态受影响范围（GeoServer GA）：2.24.5、2.25.3–2.25.7、2.26.0–2.26.4、
2.27.0–2.27.5、2.28.0–2.28.4、3.0.0。无 PostgreSQL/PostGIS 数据存储的图层不适用。
impact:
攻击者可在数据存储数据库角色权限内执行堆叠 SQL。若该角色为 superuser 或
持有 pg_execute_server_program，才可能进一步在数据库服务器上执行 OS 命令。
remediation:
将 PostGIS 数据存储账号降为最小权限，撤销 superuser 与 pg_execute_server_program；
限制匿名 WFS CQL_FILTER；升级到已修复 jsonArrayContains 原始拼接的 GeoTools/GeoServer。
reference:
- [https://github.com/mhtsec/GeoServer-jsonArrayContains-PG-RCE](https://github.com/mhtsec/GeoServer-jsonArrayContains-PG-RCE)
- [https://github.com/geotools/geotools/commit/651ee8784230fb5476928a2daba8129123ace140](https://github.com/geotools/geotools/commit/651ee8784230fb5476928a2daba8129123ace140)
- [https://osgeo-org.atlassian.net/browse/GEOT-7589](https://osgeo-org.atlassian.net/browse/GEOT-7589)
classification:
cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
cvss-score: 9.8
cwe-id: CWE-89
cpe: cpe:2.3:a:osgeo:geoserver:*:*:*:*:*:*:*:*
metadata:
verified: false
max-request: 30
vendor: osgeo
product: geoserver
shodan-query: title:"geoserver"
fofa-query: app="GeoServer"
tags: geoserver,sqli,cql,wfs,postgis,postgresql
flow:
http(1)
f…（脚本共 5225 字，完整版见原文）
```
- **预期**：200　|　—