<?php
$callbacks = array('callback', 'another_callback');
$callback = $_GET['callback'];
$arguments = $_GET['arguments'];
function callback($args){
	echo 'function called with arguments';
}
if (in_array($callback, $callbacks)) {
	$callback($arguments);
	//$func = new ReflectionFunction($callback); $func->invoke($arguments);
	// create_function also vulnerable // create_function('$foobar', "echo $foobar;");
}
?>