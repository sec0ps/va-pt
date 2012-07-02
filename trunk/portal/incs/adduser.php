<?php

//require 'sessman.inc';
require 'connect.php';

$username=$conn->real_escape_string(strip_tags(substr($_POST['username'],0,32)));
//$realname=$conn->real_escape_string(strip_tags(substr($_POST['realname'],0,60)));
$password=sha1($_POST['password']);
$password1=sha1($_POST['password1']);
$email=$conn->real_escape_string(strip_tags(substr($_POST['email'],0,50)));

//$hid=sha1($_POST['username']);

if ( !$username ) {
        echo "You must enter the name you will use to access the system in the Username field";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}

// will be included in later version
//if ( !$realname ) {
//        echo "You must enter your full name in the Full Name field";
//        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
//  exit;
//}

if ( !$email ) {
        echo "You must enter your email address in the Email Address field";
       echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
} 

if (!eregi("^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$", $_POST['email'])) {
        echo "The Email you entered was not in the proper format, please go back and enter a valid Email address";       
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
 exit;
}

 if ( $password !== $password1 ) {
        echo "Entered Password do not match. Please go back and re-enter your passwords.";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}

 if (strlen($_POST['password']) < 6 || (strlen($_POST['password']) > 15 )) {
        echo "Password must be at minimum 6 characters and at maximum 15 characters";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
    exit;
}

// will be included in the ready for prime time version
//if (!(ereg("[A-Z]",$_POST['password']) &&
//      ereg("[a-z]",$_POST['password']) &&
//      ereg("[0-9]",$_POST['password']) &&
//      ereg("[^A-Za-z0-9]",$_POST['password']))) 
// { 
//       echo "Please enter a password that contains one Upper case character, one lower case character and one number";
//       echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
//exit;
//}

// verify the username does not already exist in the database

        $query = "select username from users where username = '".$username."'";
        $result = $conn->query($query);
        $num = mysqli_num_rows ($result);

        if ($num == 1) {
        echo "The username you have selected has already been taken, please select a new name";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
    exit;
}

// insert user record into the database
     
//$query = "insert into users (username, password, realname, email, role, status, hid) values ('".$username."','".$password."','".$realname."','".$email."','0','0','".$hid."')";
$query = "insert into users (username, password, email, status) values ('".$username."','".$password."','".$email."','0')";
     $result = $conn->query($query);

     if($result) {

        echo $conn->affected_rows." user added to the database";
        header("location:../main.php");

 } else {

        echo "An error has occured, user has not been added to the database" .$conn->error;

}
$conn->close();

?>
