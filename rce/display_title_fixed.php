<?php
$title = preg_replace("/[^A-Za-z0-9_]/","",$_GET['title']);
eval('echo Welcome'.$title.';');
?>