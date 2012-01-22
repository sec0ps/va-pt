<?php

require 'connect.php';

  $name = $conn->real_escape_string(strip_tags(substr($_POST['username'],0,32)));
  $password = $conn->real_escape_string(strip_tags(substr($_POST['password'],0,32)));

$shapass = sha1($password);
$hid = sha1($name);
$username = $_POST['username'];

if ( !$name ) {
        echo "You must enter your username in the Username field";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}

if ( !$password ) {
        echo "You must enter your password in the Password field";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}

     // query the database to see if there is a record which matches
     $query = "select count(*) from users where username = '".$name."' and password = '".$shapass."'";

     $result = mysqli_query($conn, $query);
     if(!$result) {
       echo "Cannot run query.";
       exit;
     }
     $row = mysqli_fetch_row($result);
     $count = $row[0];

    if ($count > 0) {
      // name and password combination are correct
	session_start();
        $_SESSION["hid"] = $hid;
	$_SESSION["username"] = $name;
        header("location:../application/index.php");
    } else {
      // name and password combination are not correct
      echo "Your Username or Password is incorrect or your account has not yet been authorized.</p>";
      echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
    }
$conn->close();
?>

