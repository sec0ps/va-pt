<?php
session_start();
session_destroy();
$newurl = "https://" . $_SERVER["SERVER_NAME"];
header("Location: $newurl");
?>
