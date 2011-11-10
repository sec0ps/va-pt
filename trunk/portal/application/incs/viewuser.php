<?php
// connect to the database
 include('connect.php');

// get the records from the database
if ($result = $conn->query("SELECT id, username, realname, email FROM users ORDER BY id"))
  {
// display records if there are records to display
   if ($result->num_rows > 0)
   {
// display records in a table
 echo "<table border='1' cellpadding='10'>";
// set table headers
 echo "<tr><th>Username</th><th>Real Name</th><th>Email</th><th></th></tr>";
 while ($row = $result->fetch_object())
 {
 // set up a row for each record
 echo "<tr>";
 echo "<td>" . $row->username . "</td>";
 echo "<td>" . $row->realname . "</td>";
 echo "<td>" . $row->email . "</td>";
 echo "<td><a href='incs/delete.php?id=" . $row->id . "'>Delete</a></td>";
 echo "</tr>";
 }
echo "</table>";
}
// if there are no records in the database, display an alert message
  else
{
  echo "No results to display!";
  }
}
  // show an error if there is an issue with the database query
  else
  {
 echo "Error: " . $conn->error;
}
// close database connection
$conn->close();
?>
