<?php

//if($_SERVER["HTTPS"] != "on") {
//    $newurl = "https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
//    header("Location: $newurl");
//    exit();
//} 

if (!isset($_SESSION['hid'])) // ;
{
 $newurl = "http://" . $_SERVER["SERVER_NAME"];
 header("Location: $newurl");
}

?>

