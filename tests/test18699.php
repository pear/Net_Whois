<?php
require_once "Net/Whois.php";
$whois = new Net_Whois();
echo $whois->query('magazine-deutschland.de');
