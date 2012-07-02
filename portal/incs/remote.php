<?php
if ($_SERVER['REMOTE_ADDR'] != '127.0.0.1') {
echo "<meta http-equiv='refresh' content='5; URL=http://www.google.com'>";
echo "Remote connections to this portal are not permitted at this time..redirecting you elsewhere";
exit;
}
?>