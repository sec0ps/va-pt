<?php
session_start();
session_destroy();
$newurl = "http://" . $_SERVER["SERVER_NAME"];
header("Location: $newurl");
?>
