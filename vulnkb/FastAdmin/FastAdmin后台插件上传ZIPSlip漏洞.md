# FastAdmin后台插件上传ZIPSlip漏洞

- **系统**：FastAdmin　|　**类型**：文件上传　|　**CVE**：—

**请求体 / payload**
```
查看目录发现写入成功
```

**其他**
- 1. 漏洞触发路径: ```plain
插件管理 → 本地安装 → 上传ZIP文件 → 自动解压 → 目录遍历写入
```
- 2. 核心代码分析: 本身这段代码是安全的，因为本地导入插件会使用文件的md5与官网进行校验，只有存在于官网的插件才能被导入，但是在我上网搜索相关信息时发现网上存在不少去除限制教程，推测有不少人为了安装非官方插件而选择去除，在实际测试中可以尝试一下，说不定会撞大运呢，漏洞位于 <code>vendor/fastadminnet/fastadmin-addons/src/addons/Service.php</code> 文件中：
```plain
// 第156行：文件上传限制
$uploadFile = $file->rule('uniqid')->validate([
    'size' => 102400000,
    'ext' => 'zip,fastaddon'  // 只允许zip和fastaddon文件
])->move($addonsTempDir);
// 第205行：MD5验证
$e
- 3. 漏洞成因: 1. **路径未过滤**：<code>$zip->extractTo($addonDir)</code> 直接解压，未检查ZIP内文件路径
2. **目录遍历**：ZIP文件中可包含 <code>../../../</code> 等路径遍历字符
- 步骤1：访问插件管理: 导航至：<code>系统管理</code> → <code>插件管理</code> → <code>本地安装</code>