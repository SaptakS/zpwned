<?php
include 'util.php';
if (!isLoggedIn()) {
	echo 'Not Authorized';
	die();
}
$type = $_REQUEST['type'];
switch ($type) {
	case 'delete_user':
		$user_id = $_REQUEST['user_id'];
		// delete user
		echo "user deleted successfully :)";
		break;
	default:
		break;
}
?>