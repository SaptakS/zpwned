<?php
$user_id = $_GET['user_id'];
$path = dirname(__FILE__).'/'.$user_id;
if (!file_exists($path)){
	system('mkdir '.$path);
}
// upload picture
?>