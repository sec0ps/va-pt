<?php
// destroy previous session
session_start();
session_regenerate_id();

require 'incs/connect.php';
require 'incs/define.php';
require 'incs/sessman.inc';

?>

<html>
<head>
<title><?php echo title; ?></title>

<link rel="stylesheet" type="text/css" href="incs/index.css" />

</head>
<body>

<div class="application">
 <h1><?php echo title; ?></h1>
 <hr />
 <p><?php echo description; ?></p>
</div>

<div class="application">

<?php

// get the records from the database
if ($result = $conn->query("select * from projects ORDER by id"))
{
// display records if there are records to display
        if ($result->num_rows > 0)
{
// display records in a table
echo "<table border='1' cellpadding='5'>";
// set table headers
echo "<tr><th>Description</th><th>Platform</th><th>Type</th><th>File</th></tr>";

while ($row = $result->fetch_object())
{
// set up a row for each record
echo "<tr>";
echo "<td>" . $row->projname . "</td>";
echo "<td>" . $row->custcontact . "</td>";
echo "<td>" . $row->custphone . "</td>";
echo "<td>" . $row->custemail . "</a></td>";
echo "</tr>";
}
 echo "</table>";
}
// if there are no records in the database, display an alert message
else
 {
  echo "No projects to display!";
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

</div>

<div class="logout">
Logged in as: <?php echo $_SESSION['username'] ?> | <a href="incs/logout.php">logout</a> 
</div>

<?php require 'incs/menu.inc' ?>

</body>
</html>