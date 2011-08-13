<?php
require_once "Net/Whois.php";

$tld  = "de";     // get information about this tld
$whois = new Net_Whois;
$data = $whois->getDomainServer($tld);
echo $data;
?>
