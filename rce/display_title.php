<?php
$title = $_GET['title'];
eval('echo Welcome'.$title.';');
// assert() also vulnerable
?>