<?php

if($_SERVER["HTTPS"] != "on") {
    $newurl = "https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
    header("Location: $newurl");
    exit();
} 

?>
