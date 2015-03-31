<?php
session_start();
session_regenerate_id();

//require 'connect.php';
//require 'define.php';
require 'sessman.inc';

?>

 <?php 
 $target = "../uploads/"; 
 $target = $target . basename( $_FILES['uploaded']['name']) ;  
 
  $allowedExtensions = array("txt","csv","xml");
  foreach ($_FILES as $file) {
    if ($file['tmp_name'] > '') {
      if (!in_array(end(explode(".",
            strtolower($file['name']))),
            $allowedExtensions)) {
       die($file['name'].' is an invalid file type!<br/>'.
        '<a href="javascript:history.go(-1);">'.
        '&lt;&lt Go Back</a>');
    }
  }
}
 
 if ($_FILES["uploaded"]["error"] > 0)
 {
 	echo "Error: " . $_FILES["file"]["error"] . "<br />";
}
 if ($_FILES["uploaded"]["size"] > 350000) 
 { 
 echo "Your file is too large.<br>"; 
 } 
 
 if(move_uploaded_file($_FILES['uploaded']['tmp_name'], $target)) 
 { 
 echo "<meta http-equiv='refresh' content='3; URL=../main.php'>"; 
 echo "The file ". basename( $_FILES['uploaded']['name']). " has been uploaded<br />"; 
 echo "Redirecting you back to the main page...";
 } 
 else 
 { 
 echo "Sorry, there was a problem uploading your file."; 
 } 
// } 
 ?>  

<!-- need to add the import into mysql here for this to be complete -->