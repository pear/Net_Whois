
<?php
require_once "Net/Whois.php";

$server = "whois.denic.de";
$query  = "phpcrawler.de";     // get information about
                               // this domain
$whois = new Net_Whois;
$data = $whois->query($query, $server);
echo $data;
?>

