<?php
$string = $_GET['string'];
print preg_replace('/^(.*)/e', 'strtoupper("\\1")', $string);
?>