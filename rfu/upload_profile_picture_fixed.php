<?php
$size = getimagesize($_FILES['picture']['tmp_name']);
if (!$size) {
	echo 'Upload Image file :p';
	die();
}
$filename = trim(pathinfo($_FILES['picture']['name'])['filename']); //or random filename
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename.'.jpg')){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>