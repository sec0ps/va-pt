<?php
session_start();
session_regenerate_id();

require 'incs/define.php';
require 'incs/remote.php';
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
 <form action="result.php" method="post">
  <input type="text" name="dbstring" size="25">
  <input type="submit" value="Search Databases &gt;&gt;" />
 </form>
</div>

<div class="application">
<font size=2>
<p><b><u>The Vulnerability Assessment and Penetration Testing Toolkit - Vulnerability and Exploit Search Portal</b></u></p>

<p>The Vulnerability and Exploit Search Portal will be migrated into the overall project management framework once it is completed.<br>
It will be distributed as part of the overall "The Risk Assessment, Vulnerability Assessment and Penetration Testing Management Portal"</p>

<p>The kit is being provided during development under <a href="http://www.gnu.org/licenses/old-licenses/gpl-2.0.html" target="_blank">GNU GPLv2</a></p>

<p>If you have any comments, questions, suggestions or to report bugs, please use the <a href="http://code.google.com/p/va-pt/issues/list" target="_blank">Issue Tracker</a> on Google Code.</p> 

<p>Thanks,<br>
Keith Pachulski<br> 
Twitter: <a href="https://twitter.com/#!/sec0ps" target="_blank">@sec0ps</a><br>
Email: <a href="mailto:enforce570@gmail.com">enforce570@gmail.com</a>

</font>
</div>
</body>
</html>
