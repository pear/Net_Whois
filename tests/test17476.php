<?php
/**
 * test17476.php
 * 09-Jun-2010
 *
 * PHP Version 5
 *
 * @category test17476
 * @package  test17476
 * @author   Ken Guest <ken.guest@blacknight.com>
 * @license  GPL (see http://www.gnu.org/licenses/gpl.txt)
 * @version  CVS: <cvs_id>
 * @link     test17476.php
 * @todo
*/



?>
<?php
$q=isset($_REQUEST['q'])?htmlspecialchars($_REQUEST['q']):NULL;
$s=isset($_REQUEST['s'])?htmlspecialchars($_REQUEST['s']):NULL;
$q = 'test.com';
if (strchr($q,'.')) {
    require_once "Net/Whois.php";
    $whois = new Net_Whois;
    $q=strtolower($q);
    if (!$s && $q[0] == '.') {
        $s='whois.iana.org';
    }
    $q=trim($q,'.');
    $tld=pathinfo($q,PATHINFO_EXTENSION);
    if ($tld=='com') {
        $whois->setAuthoritative(1);
    } elseif ($tld=='name') {
        $q='domain = '.$q;
    }
    $data=htmlspecialchars($whois->query($q,$s));
    echo "<pre>$data</pre>";
}
?>
