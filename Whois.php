<?php
// $Id$
// +----------------------------------------------------------------------+
// | PHP version 4.0                                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2001 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.02 of the PHP license,      |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Sebastian Nohn <sebastian@nohn.net>                         |
// +----------------------------------------------------------------------+

require_once 'PEAR.php';
require_once 'Net/Socket.php';

/**
 * PEAR's Net_Whois:: interface. Provides functions
 * useful for Whois-Queries.
 * @version 0.1
 * @author Sebastian Nohn <sebastian@nohn.net>
 */

class Net_Whois extends PEAR {

    /**
    * Implements Net_Whois::query() function using PEAR's socket
    * functions
    * 
    * @param string  The whois-server to query
    *
    * @param string  The whois database object to lookup
    *
    * @return string The data returned from the whois-server
    */
    
    function query($server, $query)
    {
        $socket = new Net_Socket;
        $fp = $socket->connect($server, 43); 
        if (!$fp) { 
            $data = "Error connecting to $server";
        } else { 
            $query .= "\n"; 
            $socket->write($query); 
            $data = $socket->read(16384); 
            $socket->disconnect();
        } 
        return $data; 
    } 
} 
?>
