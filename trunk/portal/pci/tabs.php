<link rel="stylesheet" type="text/css" href="pci/tab-view.css" />

<?php $id = isset($_GET['id']) ? $_GET['id'] : 1; ?>

<div class="TabView" id="TabView">

<div class="Tabs" style="width: 1300px;">
  <a <?=($id == 1) ? 'class="Current"' : 'href="pci.php?id=1"';?>>Requirement 1</a>
  <a <?=($id == 2) ? 'class="Current"' : 'href="pci.php?id=2"';?>>Requirement 2</a>
  <a <?=($id == 3) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 3</a>
  <a <?=($id == 4) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 4</a>
  <a <?=($id == 5) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 5</a>
  <a <?=($id == 6) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 6</a>
  <a <?=($id == 7) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 7</a>
  <a <?=($id == 8) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 8</a>
  <a <?=($id == 9) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 9</a>
  <a <?=($id == 10) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 10</a>
  <a <?=($id == 11) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 11</a>
  <a <?=($id == 12) ? 'class="Current"' : 'href="pci.php?id=3"';?>>Requirement 12</a>
</div>

<div class="Pages" style="width: 1300px; height: 400px;">
  <div class="Page" style="display: <?=($id == 1) ? 'block' : 'none';?>"><div class="Pad">Page 1</div></div>
  <div class="Page" style="display: <?=($id == 2) ? 'block' : 'none';?>"><div class="Pad">Page 2</div></div>
  <div class="Page" style="display: <?=($id == 3) ? 'block' : 'none';?>"><div class="Pad">Page 3</div></div>
  <div class="Page" style="display: <?=($id == 4) ? 'block' : 'none';?>"><div class="Pad">Page 4</div></div>
  <div class="Page" style="display: <?=($id == 5) ? 'block' : 'none';?>"><div class="Pad">Page 5</div></div>
  <div class="Page" style="display: <?=($id == 6) ? 'block' : 'none';?>"><div class="Pad">Page 6</div></div>
  <div class="Page" style="display: <?=($id == 7) ? 'block' : 'none';?>"><div class="Pad">Page 7</div></div>
  <div class="Page" style="display: <?=($id == 8) ? 'block' : 'none';?>"><div class="Pad">Page 8</div></div>
  <div class="Page" style="display: <?=($id == 9) ? 'block' : 'none';?>"><div class="Pad">Page 9</div></div>
  <div class="Page" style="display: <?=($id == 10) ? 'block' : 'none';?>"><div class="Pad">Page 10</div></div>
  <div class="Page" style="display: <?=($id == 11) ? 'block' : 'none';?>"><div class="Pad">Page 11</div></div>
  <div class="Page" style="display: <?=($id == 12) ? 'block' : 'none';?>"><div class="Pad">Page 12</div></div>
</div>
</div>

<script type="text/javascript" src="pci/tab-view.js"></script>
<script type="text/javascript">
tabview_initialize('TabView');
</script>

