<?php

$host = "localhost";
$user = "vapt";
$pass = "vapt";
$db = "application";

$conn = new mysqli($host, $user, $pass, $db);

if (mysqli_connect_errno()) {
echo "Error could not connect to the database";
exit;
}
?>


