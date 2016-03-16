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
		

		
