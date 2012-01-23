<?php

//require 'sessman.inc';
require 'connect.php';

$projname=$conn->real_escape_string(strip_tags(substr($_POST['projname'],0,32)));
$custcontact=$conn->real_escape_string(strip_tags(substr($_POST['custcontact'],0,32)));
$custphone=$conn->real_escape_string(strip_tags(substr($_POST['custphone'],0,32)));
$custemail=$conn->real_escape_string(strip_tags(substr($_POST['custemail'],0,50)));

if ( !$projname ) {
        echo "You must enter the project name.";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}
if ( !$custcontact ) {
        echo "You must enter the customer contact information.";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}
if ( !$custphone ) {
        echo "You must enter the customer phone number.";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}
if ( !$custemail ) {
        echo "You must enter the customer email address.";
        echo "<p><a href='javascript:history.back(1);'>Back</a></p>";
  exit;
}
$query = "insert into projects (projname, custcontact, custphone, custemail) values ('".$projname."','".$custcontact."','".$custphone."','".$custemail."')";
     $result = $conn->query($query);

     if($result) {

        echo $conn->affected_rows." Project has been created.";
        echo "<p><a href='../main.php'>Return to Portal</a></p>";
  exit;
 } else {

        echo "An error has occured, project has not been added to the database" .$conn->error;

}
$conn->close();

?>
