<?php
// destroy previous session
session_start();
session_regenerate_id();

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

<div class="logout">
Logged in as: <?php echo $_SESSION['username'] ?> | <a href="incs/logout.php">logout</a>
</div>

<div class="application">
<!-- About information -->
<font size=2>
<p><b><u>The VA/PT Vulnerability Assessment and Penetration Testing Mangement Toolkit.</b></u></p>

<p>This kit was created for the purpose of having a single portal that can be used for the tracking of engagements,<br>
the storage of information gather during the course of vulnerability assessments, penetration tests and control<br>
assessments (PCI-DSS, NIST, ISO, etc).</p>

<p>The kit is being provided during development under <a href="http://www.gnu.org/licenses/old-licenses/gpl-2.0.html" target="_blank">GNU GPLv2</a></p>

<p>If you have any comments, questions, suggestions or to report bugs, please use the <a href="http://code.google.com/p/va-pt/issues/list" target="_blank">Issue Tracker</a> on Google Code.</p> 

<p>Thanks,<br>
Keith Pachulski<br> 
Twitter: <a href="https://twitter.com/#!/sec0ps" target="_blank">@sec0ps</a><br>
Email: <a href="mailto:enforce570@gmail.com">enforce570@gmail.com</a>

</font>
</div>

<?php require 'incs/menu.inc' ?>

</body>
</html>
