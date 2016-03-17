<?php

foreach ($_GET as $key => $value) {
	$$key = $value;
}
//extract($_GET);
//parse_str($_GET);

function isLoggedIn(){
	return $_SESSION['isLoggedIn'];
}

if (isLoggedIn()) {
	echo "You are logged in :)";
}
else{
	echo "you are not logged in :(";
	die();
}

?>