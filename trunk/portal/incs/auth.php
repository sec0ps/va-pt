<?php

require 'connect.php';

  $name = $conn->real_escape_string(strip_tags(substr($_POST['username'],0,32)));
  $password = $conn->real_escape_string(strip_tags(substr($_POST['password'],0,32)));

$date = date("l, F d, Y h:i" ,time());
$hid = sha1($name, $date);
$username = $_POST['username'];
$shapass = sha1($password);

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
        header("location:../main.php");
    } else {

//$deny = "update users set failures = failures +1, last_failure = now(), where username = "'.$name.'"

      // name and password combination are not correct
      echo "Your Username or Password is incorrect or your account has not yet been authorized.</p>";
      echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
    }
$conn->close();
?>

