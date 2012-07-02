<?php

if ($_SERVER['REMOTE_ADDR'] != '127.0.0.1')
exit( print "Connections to this portal are not permitted at this time from remote systems" );

if (!isset($_SESSION['hid'])) // ;
{
 $newurl = "http://" . $_SERVER["SERVER_NAME"];
 header("Location: $newurl");
}

?>
