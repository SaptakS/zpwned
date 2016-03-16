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