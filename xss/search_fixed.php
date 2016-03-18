<?php
$query = htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
$user_id = $_GET['user_id'];
echo "You searched for ".$query;
?>
<script type="text/javascript">
var user = '<?php echo filter_var($user_id, FILTER_VALIDATE_INT)?>';
</script>