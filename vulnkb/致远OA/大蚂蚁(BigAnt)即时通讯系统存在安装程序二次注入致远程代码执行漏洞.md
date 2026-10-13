# 大蚂蚁(BigAnt)即时通讯系统存在安装程序二次注入致远程代码执行漏洞

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="即时通讯系统"`
- **请求**：`POST /?m=Addin&c=Pedometer&a=uploadImgCallback HTTP/1.1`

**请求体 / payload**
```
漏洞分析
先看安装程序的安装流程 Application/Install/Controller/InstallController.class.php 分为如下几个步骤
其中在初始化的部分检测是否存在安装文件 data/install.lock
如果存在则会直接退出，否则进入下一步，其中在第二步创建数据库的部分存在如下代码
**深入探索**
安装
安装程序
服务器
其中调用了 sp_create_config() 方法进行配置文件的创建，而配置文件信息由用户提供
**深入探索**
应用
即时通讯
应用程序
其中对部分字段如domain、email等有正则校验
**深入探索**
数据库
即时通信
SERVER
但是其余字段如数据库的dbtype、dbhost、dbname、dbuser、dbpwd等字段没有校验，被直接传递给sp_create_config() 方法，看下它的实现方式
function sp_create_config($config){
sp_show_msg(L('_CREATE_CONFIG_PAGE_'));
//windows的系统用GBK ，否则用 UTF-8,这个编码主要是文件系统时用到
$os = strtoupper(substr(PHP_OS,0,3))==='WIN'?'windows':'linux';
$config['CHARSET_OUT'] = $os == 'windows'?'GBK':'UTF-8';
$config['DEFAULT_LANG'] = C('DEFAULT_LANG');
if(is_array($config)){
//读取配置内容
$conf = file_get_contents(MODULE_PATH . 'Data/config.php');
//替换配置项
foreach ($config as $key => $value) {
$conf = str_replace("#{$key}#", $value, $conf);
//写入应用配置文件
if(file_put_contents( 'Application/Common/Conf/config.php', $conf)){
sp_show_msg(L('_CONFIG_WRITE_SUCCESS_'));
} else {
sp_show_msg(L('_CONFIG_WRITE_FALIED_'), 'error');
session('error', true);
**深入探索**
application
计算机安全
ERP
读取 Application/Install/Data/config.php配置文件模板，然后进行替换操作
替换前端传过来的配置信息后，写入Application/Common/Conf/config.php文件中，如果我们可以找到一个文件删除/重命名[漏洞](https://mrxn.net/tag/漏洞)，删除掉/重命名data/install.lock，那么就可以二次安装代码注入了。
经过搜索，在 Application/Addin/Controller/PedometerController.class.php找到了一处比较简单的方法 uploadImgCallback()
虽然此方法需要鉴权，但是可以通过其他方式如鉴权绕过、或者弱口令、钓鱼等方式获取到一个用户权限，重点看下它的实现方式
function uploadImgCallback(){
$userId = I('…（脚本共 3436 字，完整版见原文）
```
- **预期**：200　|　—