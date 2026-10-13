# 泛微OA-V10.76补丁分析-seccategorySQL注入

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`GET /api/ec/dev/table/getxml?dataKey=628a12ff-5528-46d7-9092-0deee8460e88_3B78D7B6E027F6615DA80BE763F33661 HTTP/1.1`

**请求体 / payload**
```
select t1.id,t1.id
docstatus_id,t1.seccategory,t1.docvestin,t1.doclastmoddate,t1.doclastmodtime,t1.docsubject,t1.docext
endname,t1.doccreaterid,t1.secretLevel,t1.ownerid,t1.docstatus,t1.doccreatedate,t1.doccreatetime,t1.a
ccessorycount,t1.replaydoccount,t1.sumDownload,t1.sumReadCount,t1.sumMark,t1.docpubdate,t1.d
ocpubtime,t1.docapprovedate,t1.docapprovetime from DocDetail t1 where t1.docstatus in(1,2,5)
and (t1.ishistory is null or t1.ishistory = 0) and (t1.isreply is null or t1.isreply='' or t1.isreply='0')
and (t1.seccategory in ( 99999 ) or (t1.seccategory in(1) and t1.docpublishtype='2'))…（脚本共 945 字，完整版见原文）
```

**其他**
- 修复建议: + 立即升级至泛微[e-cology 10.76](https://zhi.oscs1024.com/tag/e-cology-10-76)或更高安全版本
+ 升级前应参考官方升级指南进行环境检查和数据备份
+ 升级完成后验证/api/doc/out/more/list和/api/ec/dev/table/counts接口的参数过滤机制是否生效
+ 定期关注泛微官方安全公告(https://www.weaver.com.cn/cs/security/)，及时获取安全更新