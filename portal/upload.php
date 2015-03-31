<?php
session_start();
session_regenerate_id();
require 'incs/define.php';
require 'incs/sessman.inc';
?>
<html>
<head>
<script type="text/javascript">
function validateForm()
{
var x=document.forms["fupload"]["uploaded"].value;
if (x==null || x=="")
  {
  alert("You must enter the file to uploaded");
  return false;
  }
}
</script>
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
<form action="incs/upload_file.php" name="fupload" method="post" enctype="multipart/form-data" onsubmit="return validateForm()">
<input type="file" name="uploaded"/>
<input type="submit" name="submit" value="Submit" />
</form>
</div>

<div class="application">
Upload XML data from Nexpose Vulnerability Assessment Software.
</div>

<div class="logout">
Logged in as: <?php echo $_SESSION['username'] ?> | <a href="incs/logout.php">logout</a> 
</div>

<?php require 'incs/menu.inc' ?>

</body>
</html>
