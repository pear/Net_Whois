<?php
require_once 'Net/Whois.php';
$nw = new Net_Whois;
$nw->authoritative = true;
echo $nw->query ("facebook.com");

?>
