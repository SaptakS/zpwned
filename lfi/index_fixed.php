<html>
	<body>
		<?php
		$allowedThemes = array('pink.php', 'black.php');
		$theme = $_GET['theme'].'.php';
		if(in_array($theme, $allowedThemes)){
    		include 'themes/'.$theme;
		}
		else{
			echo "Theme not allowed :(";
		}
		?>
		<h1>Hello Zomato!</h1>
	</body>
</html>