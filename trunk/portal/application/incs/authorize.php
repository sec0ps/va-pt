<?php

if (!isset($_SESSION['hid'])) // ;
{
 $newurl = "https://" . $_SERVER["SERVER_NAME"];
 header("Location: $newurl");
}

?>
