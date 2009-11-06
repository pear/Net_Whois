<?php
require_once "Net/Whois.php";
$whois = new Net_Whois;
$data = $whois->query("=THIS-DOMAIN-FOR-SALE.COM",
"com.whois-servers.net");
echo nl2br($data);
?>
