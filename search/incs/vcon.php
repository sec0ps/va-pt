<?php

$host = "localhost";
$user = "vapt";
$pass = "vapt";
$db = "osvdb";
$db1 = "exploitdb";
$db2 = "nvd";

// $conn = new mysqli($host, $user, $pass, $db);
$conn1 = new mysqli($host, $user, $pass, $db1);
$conn2 = new mysqli($host, $user, $pass, $db2);

if (mysqli_connect_errno()) {
echo "Error could not connect to the database";
exit;
}
?>


