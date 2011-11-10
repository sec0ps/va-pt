<link rel="stylesheet" type="text/css" href="tabs/tab-view.css" />

<?php $id = isset($_GET['id']) ? $_GET['id'] : 1; ?>

<div class="TabView" id="TabView">

<div class="Tabs" style="width: 700px;">
  <a <?=($id == 1) ? 'class="Current"' : 'href="search/search.php?id=1"';?>>Vulnerability Search</a>
  <a <?=($id == 2) ? 'class="Current"' : 'href="sample.php?id=2"';?>>Tab 2</a>
  <a <?=($id == 3) ? 'class="Current"' : 'href="sample.php?id=3"';?>>Tab 3</a>
</div>

<div class="Pages" style="width: 1100px; height: 500px;">
  <div class="Page" style="display: <?=($id == 1) ? 'block' : 'none';?>"><div class="Pad">Page 1</div></div>
  <div class="Page" style="display: <?=($id == 2) ? 'block' : 'none';?>"><div class="Pad">Page 2</div></div>
  <div class="Page" style="display: <?=($id == 3) ? 'block' : 'none';?>"><div class="Pad">Page 3</div></div>
</div>
</div>

<script type="text/javascript" src="tabs/tab-view.js"></script>
<script type="text/javascript">
tabview_initialize('TabView');
</script>

