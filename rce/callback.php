<?php
$callback = $_GET['callback'];
$arguments = $_GET['arguments'];
function callback($args){
	echo 'function called with arguments';
}
$callback($arguments);
//$func = new ReflectionFunction($callback); $func->invoke($arguments); also same
// create_function also vulnerable // create_function('$foobar', "echo $foobar;");
?>