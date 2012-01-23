<?php
	class HostProperties{
		var $host_ip;
		var $os;
	}
	
	class Ports{
		var $port;
		var $service_name;
		var $protocol;
		var $severity;
		var $risk_factor;
		var $description;
		var $synopsis;
		var $see_also;
		var $plugin_output;
	}
	
	$hostProperties = new HostProperties();
	$ports = array();	
	$file = file_get_contents("Nessus-10.25.0.118.nessus");
	$xml = new SimpleXMLReader($file);
	
	$i=0;
	//Start from the Report block
	foreach($xml->Report as $report){
		//All report items are under ReportHost
		foreach($host->ReportHost as $host){
			$hostProperties->host_ip = $host["name"];
			//Parse HostProperties
			foreach($host->HostProperties as $host_properties){
				foreach($host_properties->tag as $tags){
					if($tags["name"]=="operating-system"){
						$hostProperties->os=$tags;
					}
				}
			}
			foreach($host->ReportItem as $item){
				$ports[$i] = new Ports();
				if(!(is_null($item["port"]))){
					$ports[$i]->port = $item["port"];
				}
				if(!(is_null($item["svc_name"]))){
					$ports[$i]->service_name = $item["svc_name"];
				}
				if(!(is_null($item["protocol"]))){
					$ports[$i]->protocol = $item["protocol"];
				}
				if(!(is_null($item["severity"]))){
					$ports[$i]->protocol = $item["severity"];
				}
				if(!(is_null($item->solution))){
					$ports[$i]->solution = $item->solution;
				}
				if(!(is_null($item->risk_factor))){
					$ports[$i]->risk_factor = $item->risk_factor;
				}
				if(!(is_null($item->description))){
					$ports[$i]->description = $item->description;
				}
				if(!(is_null($item->synopsis))){
					$ports[$i]->synopsis = $item->synopsis;
				}
				$j=0;
				foreach($item->see_also as $see_also){
					$ports[$i]->see_also[$j++]=$see_also;
				}
				if(!(is_null($item->plugin_output))){
					$ports[$i]->plugin_output = $item->plugin_output;
				}
				$i++;
			}
		}
	}
	
?>

<html>
	<head><title>Nessus Test</title></head>
	<body>
		<h1>This is a test of my script</h1>
		<p>Host IP: <?php $hostProperties->host_ip; ?></p>
		<p>Operating System: <?php $hostProperties->os; ?></p>
		<?php
			foreach($ports as $port){
				echo "Port No: ".$port->port."<br />";
				echo "Service Name: ".$port->service_name."<br />";
				echo "Protocol: ".$port->protocol."<br />";
				echo "Severity: ".$port->severity."<br />";
				echo "Solution: ".$port->solution."<br />";
				echo "Description: ".$port->description."<br />";
				echo "Synopsis: ".$port->synopsis."<br />";
				foreach($port->see_also as $seeAlso){
					echo "See Also: ".$seeAlso."<br />";
				}
				echo "Plugin Output: ".$port->plugin_output."<br />";
			}
		?>
	</body>
</html>
			









		
