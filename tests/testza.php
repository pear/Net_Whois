<?php
require_once 'Net/Whois.php';
$nw = new Net_Whois;
echo $nw->query ('ananzi.co.za');

?>
