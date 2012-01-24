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
<form action="incs/upload_file.php" method="post"
enctype="multipart/form-data">
<label for="file">Filename:</label>
<input type="file" name="file" id="file" />
<input type="submit" name="submit" value="Submit" />
</form>
</div>

<div class="application">
Upload XML data for Nessus, Nexpose or Nmap results here to be processed.
</div>

<div class="logout">
Logged in as: <?php echo $_SESSION['username'] ?> | <a href="incs/logout.php">logout</a> 
</div>

<?php require 'incs/menu.inc' ?>

</body>
</html>
