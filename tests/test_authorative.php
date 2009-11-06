<?php
require_once 'Net/Whois.php';
$nw = new Net_Whois;
$nw->authorative = true;
echo $nw->query ("facebook.com");

?>
