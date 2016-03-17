<?php
include 'util.php';
if (!isLoggedIn()) {
	echo 'Not Authorized';
	die();
}
?>
<!DOCTYPE html>
<html>
<body>
<p>Welcome Admin</p>
<form action="handler" method="post">
    <input type="text" name="user_id">
    <input type="hidden" name="type" value="delete_user">
    <input type="submit" value="Delete User" name="submit">
</form>

</body>
</html>