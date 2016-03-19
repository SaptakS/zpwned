<?php
$name = $_POST['name'];
$about = $_POST['about'];
$username = $_POST['username'];
if($_SESSION['csrf_token'] != $_POST['csrf_token']){
	echo 'Wrong Token';
}
// update user info
?>