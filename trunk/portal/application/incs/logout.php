<?php
session_start();
session_destroy();
// $newurl = "https://" . $_SERVER["SERVER_NAME"];
$newurl = "http://" . $_SERVER["SERVER_NAME"];
header("Location: $newurl");
?>
