<?php

//

$luser = $_SESSION['hid'];

// pulled the username from the hid

 $query = "select username from users where hid = '".$luser."';
 $result = mysqli_query($conn, $query);
 if(!result) { 
  echo "Query failed"; 
 exit;
}
 $row = mysqli_fetch_row($result);

$conn->close();

?>
