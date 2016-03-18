<?php
$query = $_GET['q'];
$user_id = $_GET['user_id'];
echo "You searched for ".$query;
?>
<br>
<script type="text/javascript">
var user = '<?php echo $user_id?>';
</script>