<?php
session_start();
session_regenerate_id();
require 'define.php';

?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<head>
<title><?php echo title; ?></title>
<link rel="stylesheet" type="text/css" href="search.css" />
</head>
<body>
 <div class="application">
 <h1><?php echo title; ?></h1>
 <hr />
 <p><?php echo description; ?></p>
 <p></p>
 <hr />
 <p class="ms"><strong><?php echo hostname; ?></strong> <?php echo $_SERVER['HTTP_HOST']; ?></p>
 <p class="ms"><strong><?php echo run_date; ?></strong> <?php echo date("Y-m-d H:i:s"); ?></p>
 <p class="ms"><strong><?php echo search; ?></strong> <?php echo $_POST['dbstring']; ?></p>
</div>

<div class="application">
<p><a href="nvd.php">NVD</a> | <a href="expoitdb.php">ExploitDB Results</a> | <a href="index.php">New Search</a></p>

<?php
// connect to the database
include('connect.php');
// search string
$search = $_POST['dbstring'];

$_SESSION['dbstring'] = $_POST['dbstring'];

// get the records from the database
if ($result = $conn->query("select osvdb_id, title, description, short_description from vulnerabilities where short_description like '%".$search."%' ORDER by osvdb_id"))
{
// display records if there are records to display
	if ($result->num_rows > 0)
{
// display records in a table
echo "<table border='1' cellpadding='5'>";
// set table headers
echo "<tr><th>ID</th><th>Title</th><th>Description</th><th>Short Description</th></tr>";

while ($row = $result->fetch_object())
{
// set up a row for each record
echo "<tr>";
echo "<td>" . $row->osvdb_id . "</td>";
echo "<td>" . $row->title . "</td>";
echo "<td>" . $row->description . "</td>";
echo "<td>" . $row->short_description . "</td>";
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
</div>
<?php require 'footer.php' ?>
</body>
</html>
