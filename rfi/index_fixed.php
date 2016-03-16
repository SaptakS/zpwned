<html>
	<body>
		<?php
		$allowedThemes = array('pink', 'black');
		$theme = $_GET['theme'].'php';
		if(in_array($theme, $allowedThemes) && file_exists($theme)){
    		include $theme;
		}
		else{
			echo "Theme not allowed :(";
		}
		?>
		<h1>Hello Zomato!</h1>
	</body>
</html>