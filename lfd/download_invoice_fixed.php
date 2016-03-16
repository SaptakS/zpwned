<?php
$invoice = dirname(__FILE__).'/invoices/'.basename($_REQUEST['invoice']);
if (!file_exists($invoice)) {
	echo "File not found :(";
	die();
}
header("Pragma: public");
header("Expires: 0");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");

header("Content-Type: application/force-download");
header( "Content-Disposition: attachment; filename=".basename($invoice));

@readfile($invoice);
die();
?>