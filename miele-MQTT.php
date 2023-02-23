<?php
################################################################################################################################################
######
######		Miele-MQTT.php
######		Script by Ole Kristian Lona, to read data from Miele@home, and transfer through MQTT.
######		Script adjusted by Peter Wiwel, passing on json object with some crude value sanatation for OpenHab
######		Version 3.2
######
################################################################################################################################################

################################################################################################################################################
######		Global variables
################################################################################################################################################

$code='';
$mosquitto_host='';
$mosquitto_user='';
$mosquitto_pass='';
$mosquitto_port='';
$topicbase='';
$access_token='';
$config='';
$country='';
$delay=60;
$version="3.2";

################################################################################################################################################
######		getRESTData - Function used to retrieve REST data from server.
################################################################################################################################################

function getRESTData($url,$postdata,$method,$content,$authorization='')
{
	global $debug;
	global $json;
	global $folder;

	if($debug){
		print "Authorization: " . $authorization . PHP_EOL;
		if (is_array($postdata)) {
			print "Postdata: ". PHP_EOL;
			var_dump($postdata);
		}
		else {
			print "Postdata: ". $postdata . PHP_EOL;
		}
		print "Method: " . $method . PHP_EOL;
		print "URL: " . $url . PHP_EOL;
	}
	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	$headers=array();

	if(strlen($authorization)>> 0 ) {
		array_push($headers, 'Authorization: ' . $authorization);
	}
	if(strlen($content) >> 0 ) {
		array_push($headers, 'Content-Type: ' . $content);
	}


	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	if (( strcmp($method,"POST" ) == 0 ) || ( strcmp($method,"PUT" ) == 0 )) {
		curl_setopt($ch,CURLOPT_POSTFIELDS, $postdata);
	}
	$result = curl_exec($ch);

	#$tmpfname = tempnam($folder,"PHP");  ####  Used for debugging REST communications
	#file_put_contents($tmpfname, $result);  ####  Used for debugging REST communications

	if (curl_getinfo($ch,CURLINFO_RESPONSE_CODE) == 302 ) {
		$returndata=curl_getinfo($ch,CURLINFO_REDIRECT_URL);
	}
	elseif (curl_getinfo($ch,CURLINFO_RESPONSE_CODE) == 401 ) {
		$returndata=array("code"=>"Unauthorized");
		if($debug){
			print "401 - Unauthorized" . PHP_EOL;
		}		
	}
	else {
		$returndata=json_decode($result,true, JSON_UNESCAPED_UNICODE);
	}
	
 return $returndata;
}

################################################################################################################################################
######		prompt_silent - Function "borrowed" from https://www.sitepoint.com/interactive-cli-password-prompt-in-php/
######		Written by: Troels Knak-Nielsen
################################################################################################################################################
function prompt_silent($prompt = "Enter Password:") {
  if (preg_match('/^win/i', PHP_OS)) {
    $vbscript = sys_get_temp_dir() . 'prompt_password.vbs';
    file_put_contents(
      $vbscript, 'wscript.echo(InputBox("'
      . addslashes($prompt)
      . '", "", "password here"))');
    $command = "cscript //nologo " . escapeshellarg($vbscript);
    $password = rtrim(shell_exec($command));
    unlink($vbscript);
    return $password;
  } else {
    $command = "/usr/bin/env bash -c 'echo OK'";
    if (rtrim(shell_exec($command)) !== 'OK') {
      trigger_error("Can't invoke bash");
      return;
    }
    $command = "/usr/bin/env bash -c 'read -s -p \""
      . addslashes($prompt)
      . "\" mypassword && echo \$mypassword'";
    $password = rtrim(shell_exec($command));
    echo "\n";
    return $password;
  }
}


################################################################################################################################################
######		createconfig - Function to prompt for config data, and create config file.
################################################################################################################################################
function createconfig($refresh=false) {	
	$configcreated=false;
	$tokenscreated=false;
	global $folder;
	global $code;
	global $mosquitto_host;
	global $mosquitto_user;
	global $mosquitto_pass;
	global $mosquitto_port;
	global $topicbase;
	global $access_token;
	global $create;
	global $debug;
	global $country;
	
	$content="application/x-www-form-urlencoded";

	if($refresh == false) {
		$configdefault=array(
			'access_token'=> '',
			'refresh_token'=> '',
			'expiry_date' => '',
			'timetorefresh' => '5',
			'client_id'=> '',
			'client_secret'=> '',
			'country'=> '',
			'code'=> '',
			'email'=> '',
			'mosquitto_host'=> 'localhost',
			'mosquitto_user'=> '',
			'mosquitto_pass'=> '',
			'mosquitto_port'=> '',
			'topicbase'=> '/miele/'
		);
		if(file_exists($folder . '/miele-config2.php')){
			$config=array_replace($configdefault,include($folder . '/miele-config2.php'));
		}
		else {
			$config=$configdefault;
		}
		$userid=readline("Username (email) to connect with [" . $config['email'] . "]: ");
		if($userid == "") {$userid=$config["email"];}
		$password=prompt_silent("Please type your password: ");
		$timetorefresh=readline("How many days before epiry to refresh token? [" . $config['timetorefresh'] . "]: ");
		if($timetorefresh == "") {$timetorefresh=$config["timetorefresh"];}
		$country=readline('Please state country in the form of "no-NO, en-EN, etc."[' . $config["country"] . ']: ');
		if($country == "") {$country=$config["country"];}

		$client_id=readline('Please input the client ID assigned to you by Miele API administrators [' . $config["client_id"] . ']: ');
		if($client_id == "") {$client_id=$config["client_id"];}
		$client_secret=readline('Please input the Client Secret assigned to you by Miele [' . $config["client_secret"] . ']: ');
		if($client_secret == "") {$client_secret=$config["client_secret"];}

		$mosquitto_host=readline("Type the name of your mosquitto host [" . $config["mosquitto_host"] . "]: ");
		if($mosquitto_host == "") {$mosquitto_host=$config["mosquitto_host"];}
		
		$mosquitto_port=readline("Type the port of your mosquitto host [" . $config["mosquitto_port"] . "]: ");
		if($mosquitto_port == "") {$mosquitto_port=$config["mosquitto_port"];}
		
		$mosquitto_user=readline("Type login-name for Mosquitto [" . $config["mosquitto_user"] . "]: ");
		if($mosquitto_user == "") {$mosquitto_user=$config["mosquitto_user"];}
		if (strlen($mosquitto_user) >> 0 ) {
			$mosquitto_pass=readline("Type the password for your mosquitto user (will be saved in PLAIN text) [" . $config["mosquitto_pass"] . "]: ");
			if($mosquitto_pass == "") {$mosquitto_pass=$config["mosquitto_pass"];}
		}
		else {
			$mosquitto_pass="";
		}
		$topicbase=readline('Type the base topic name to use for Mosquitto [' . $config["topicbase"] . ']: ');
		if($topicbase == "") {$topicbase=$config["topicbase"];}
		if (strlen($topicbase) == 0) {
			$topicbase="miele/";
		}
		if (substr($topicbase,-1) <> "/") {
			$topicbase = $topicbase . "/";
		}
	
		$authorization='';
		$url="https://api.mcs3.miele.com/oauth/auth";
		$postdata='email=' . urlencode($userid) . '&password=' . urlencode($password) . '&redirect_uri=www.google.com&state=login&response_type=code&client_id=' . $client_id . '&vgInformationSelector=' . $country;
	
		$method="POST";
	
		$data=getRESTData($url,$postdata,$method,$content,'');
	
		if (is_array($data) == FALSE){
			if($debug){print "Oauth authentication did not return array..." . PHP_EOL;}
			$params=(explode('?',$data))[1];
			foreach (explode('&', $params) as $part) {
				$param=explode("=",$part);
				
				if(strstr($param[0],'code') <> FALSE ) {
					$code=$param[1];
				}
			}
		}
		else {
			return $configcreated;
		}
	
	}
	else {
		echo "Refreshing configuration / authorization..." . PHP_EOL;
		global $config;
		$code=$config['code'];
		$client_secret=$config['client_secret'];
		$client_id=$config['client_id'];
		$mosquitto_host=$config['mosquitto_host'];
		$mosquitto_user=$config['mosquitto_user'];
		$mosquitto_pass=$config['mosquitto_pass'];
		$mosquitto_port=$config['mosquitto_port'];
		$topicbase=$config['topicbase'];
		$country=$config['country'];
	}

	if (strlen($code) >> 0 ) {
		$url='https://api.mcs3.miele.com/thirdparty/token?client_id=' . urlencode($client_id) . '&client_secret=' . $client_secret . '&code=' . $code . '&redirect_uri=%2Fv1%2Fdevices&grant_type=authorization_code&state=token';
		$postdata="";
		$method='POST';
		$data=getRESTData($url,$postdata,$method,$content);
		if(array_key_exists("access_token",$data)) {
			$access_token = $data["access_token"];
			$refresh_token = $data["refresh_token"];
			$tokenscreated = true;
			$expires_in = $data["expires_in"];
			$date = new DateTime();
        	$date->add(new DateInterval('PT'.$expires_in.'S'));
        	$expiry_date = $date->getTimestamp();
			if($debug){print "Access token: " . $access_token . PHP_EOL;}
		}
		else {
			$tokenscreated = false;
			if($debug){print "Access token could not be created! " . PHP_EOL;}
			exit;
		}
		
	}

	if($tokenscreated == true ) {
		if($debug){print "Tokens created successfully..." . PHP_EOL;}
		$config="<?php" . PHP_EOL . "return array(" . PHP_EOL . "        'access_token'=> '" . $access_token . "'," . PHP_EOL . "        'refresh_token'=> '" . $refresh_token . "'," . PHP_EOL;
		$config = $config . "	'expiry_date'=> '" . $expiry_date . "'," . PHP_EOL;
		$config = $config . "	'timetorefresh'=> '" . $timetorefresh . "'," . PHP_EOL;
		$config = $config . "	'email'=> '" . $userid . "'," . PHP_EOL;
		$config = $config . "	'client_id'=> '" . $client_id . "'," . PHP_EOL;
		$config = $config . "	'client_secret'=> '" . $client_secret . "'," . PHP_EOL;
		$config = $config . "	'code'=> '" . $code . "'," . PHP_EOL;
		$config = $config . "	'country'=> '" . $country . "'," . PHP_EOL;
		$config = $config . "	'mosquitto_host'=> '" . $mosquitto_host . "'," . PHP_EOL;
		$config = $config . "	'mosquitto_user'=> '" . $mosquitto_user . "'," . PHP_EOL;
		$config = $config . "	'mosquitto_pass'=> '" . $mosquitto_pass . "'," . PHP_EOL;
		$config = $config . "	'mosquitto_port'=> '" . $mosquitto_port . "'," . PHP_EOL;
		$config = $config . "	'topicbase'=> '" . $topicbase . "'" . PHP_EOL;
		$config = $config . ");" . PHP_EOL . "?>" . PHP_EOL . PHP_EOL;

		if (file_exists($folder . '/miele-config2.php') == true ) {
			rename($folder . '/miele-config2.php',$folder . '/miele-config2.php.org');
		}
		if (file_put_contents($folder . "/miele-config2.php", $config) <> false ) {
			if($debug){print "Configuration file created!" . PHP_EOL;}
			$configcreated=true;
		}
	}

	return $configcreated;
}


################################################################################################################################################
######		refreshtoken - Function to refresh authorization token.
################################################################################################################################################
function refreshtoken() {	
	$configcreated=false;
	$tokenscreated=false;
	global $folder;
	global $config;
	global $debug;
	global $access_token;
	
	$content="application/x-www-form-urlencoded";

	$url='https://api.mcs3.miele.com/thirdparty/token';
	#$postdata=array('client_id' => $config['client_id'], 'client_secret' => $config['client_secret'], 'refresh_token' => $config['refresh_token'], 'grant_type' => 'refresh_token');
	$postdata='client_id='. $config['client_id'] . '&client_secret=' . $config['client_secret'] . '&refresh_token=' . $config['refresh_token'] . '&grant_type=refresh_token';
	
	$method='POST';
	$data=getRESTData($url,$postdata,$method,$content);
	if(array_key_exists("access_token",$data)) {
		$access_token = $data["access_token"];
		$refresh_token = $data["refresh_token"];
		$tokenscreated = true;
		$expires_in = $data["expires_in"];
		$date = new DateTime();
		$date->add(new DateInterval('PT'.$expires_in.'S'));
		$expiry_date = $date->getTimestamp();
		if($debug){print "Access token: " . $access_token . PHP_EOL;}
	}
	else {
		$tokenscreated = false;
		if($debug){print "Access token could not be refreshed! " . PHP_EOL;}
		exit;
	}
	

	if($tokenscreated == true ) {
		if($debug){print "Tokens created successfully..." . PHP_EOL;}
		$newconfig="<?php" . PHP_EOL . "return array(" . PHP_EOL . "	'access_token'=> '" . $access_token . "'," . PHP_EOL . "	'refresh_token'=> '" . $refresh_token . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'expiry_date'=> '" . $expiry_date . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'timetorefresh'=> '" . $config['timetorefresh'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'email'=> '" . $config['email'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'client_id'=> '" . $config['client_id'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'client_secret'=> '" . $config['client_secret'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'code'=> '" . $config['code'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'country'=> '" . $config['country'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'mosquitto_host'=> '" . $config['mosquitto_host'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'mosquitto_user'=> '" . $config['mosquitto_user'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'mosquitto_pass'=> '" . $config['mosquitto_pass'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'mosquitto_port'=> '" . $config['mosquitto_port'] . "'," . PHP_EOL;
		$newconfig = $newconfig . "	'topicbase'=> '" . $config['topicbase'] . "'" . PHP_EOL;
		$newconfig = $newconfig . ");" . PHP_EOL . "?>" . PHP_EOL . PHP_EOL;

		rename($folder . '/miele-config2.php',$folder . '/miele-config2.php.org');
		if (file_put_contents($folder . "/miele-config2.php", $newconfig) <> false ) {
			if($debug){print "Configuration file created!" . PHP_EOL;}
			$configcreated=true;
		}
	}
	$config['access_token']=$access_token;
	$config['refresh_token']=$refresh_token;
	$config['expiry_date']=$expiry_date;

	return $tokenscreated;
}

################################################################################################################################################
######		checktokenrefresh - Function to check whether token is up for renewal.
################################################################################################################################################
function checktokenrefresh() {	
	global $config;
	global $debug;

	$result=true;
	if($debug){print "Checking token for expiry" . PHP_EOL; }
	$date = new DateTime();
    $diff = $config['expiry_date'] - ($date->getTimestamp());

	if($debug){print "Token expires in " . $diff . " seconds, timetorefresh is " . $config['timetorefresh'] . " days." . PHP_EOL; }
	$timetorefreshs= (int) ($config['timetorefresh'] * 3600 * 24);
	if($debug){print "Token must be refreshed with " . $timetorefreshs . " seconds left" . PHP_EOL; }
	if($diff < $timetorefreshs) {
		if($debug){print "Refreshing token..." . PHP_EOL; }
		$result=refreshtoken();
	}

	return $result;
}


################################################################################################################################################
######
######		This is the main script block
######
################################################################################################################################################
require("phpMQTT.php");

$folder=dirname($_SERVER['PHP_SELF']);

$shortopts="dDsjc";
$longopts=array("dump","debug","single","json","create");
$options=getopt($shortopts,$longopts);

# Map options to variables, to simplify further script processing...
$debug=(array_key_exists("D",$options) || array_key_exists("debug",$options));
$dump=(array_key_exists("d",$options) || array_key_exists("dump",$options));
$single=(array_key_exists("s",$options) || array_key_exists("single",$options));
$json=(array_key_exists("j",$options) || array_key_exists("json",$options));
$create=(array_key_exists("c",$options) || array_key_exists("create",$options));
if($json||$dump){$single=true;}

if ((file_exists($folder . '/miele-config2.php') == false ) || $create) {
	$configcreated=createconfig();
	if($configcreated == false) {
		exit("Failed to create config! Did you type the correct credentials?" . PHP_EOL);
	}
}

//$programPhase = include($folder.'/programphases.php');
$config = include($folder.'/miele-config2.php');
$run=true;
$count=0;

$mosquitto_host=$config['mosquitto_host'];
$mosquitto_user=$config['mosquitto_user'];
$mosquitto_pass=$config['mosquitto_pass'];
$mosquitto_port=$config['mosquitto_port'];
$topicbase=$config['topicbase'];
$code=$config['code'];
$access_token=$config['access_token'];
$country=$config['country'];

$client_id = "Miele-MQTT"; // make sure this is unique for connecting to sever - you could use uniqid()

$mqtt = new Bluerhinos\phpMQTT($mosquitto_host, $mosquitto_port, $client_id);

if(!$mqtt->connect(true, NULL, $mosquitto_user, $mosquitto_pass)) {
	exit(1);
}

if($create) {
	# Option create should exit after creating new config
	exit(0);
}

if($single) {
	checktokenrefresh();
	retrieveandpublish($folder,$mqtt);
	exit(0);
}

$topics[$topicbase . 'command/#'] = array("qos" => 0, "function" => "procmsg");
$mqtt->subscribe($topics, 0);


print "Starting MIeleMQTT version: " . $version . PHP_EOL;

$count=$delay;
while($mqtt->proc()){
	if ( $count==$delay) {
		checktokenrefresh();
		retrieveandpublish($folder,$mqtt);
		$count=0;
	}
	sleep(1);
	$count = $count + 1;
}


$mqtt->close();

function procmsg($topic, $msg){
	global $access_token;
	global $country;
	
	$commandTopic=explode('/',$topic);
	for($i = 1; $i <= 10; $i++) {
		if($commandTopic[$i] == "command") {
			$appliance=$commandTopic[$i+1];
			$action=$commandTopic[$i+2];
			$i=10;
		}
	}
	if($dump){echo "Sending command: " . $action . " to device: " . $appliance . PHP_EOL;}
	if($dump){echo $msg . PHP_EOL;}
	$url='https://api.mcs3.miele.com/v1/devices/' . $appliance . "/actions?language=";
	$url .= !empty($country) ? substr($country, 0,2) : "en"; 
	$authorization='Bearer ' . $access_token;
	$method='PUT';
	$postdata = array($action=>$msg);
	$data_json = json_encode($postdata);
	$data=getRESTData($url,$data_json,$method,'application/json',$authorization);
	if($dump){var_dump($data);}
}

exit(0);


// Retrieveing information
function retrieveandpublish($folder,$mqtt) {
	global $mosquitto_host;
	global $mosquitto_user;
	global $mosquitto_pass;
	global $mosquitto_port;
	global $access_token;
	global $topicbase;
	global $dump;
	global $json;
	global $debug;
	global $country;
	global $config;

	$authorization='';

#TESTING

#echo strlen($access_token) . PHP_EOL;

	if (strlen($access_token) >> 0 ) {
		$url='https://api.mcs3.miele.com/v1/devices?language=';
		$url .= !empty($country) ? substr($country, 0,2) : "en"; 
		$authorization='Bearer ' . $access_token;
		$method='GET';
		$data=getRESTData($url,'',$method,'application/json',$authorization);
		if (array_search("Unauthorized",$data) != "" ) {
			createconfig(true);
			$config = include($folder . '/miele-config2.php');
			$authorization='Bearer ' . $access_token;
			$method='GET';
			$data=getRESTData($url,'',$method,'',$authorization);
		}
		if ($dump) {
			var_dump($data);
		}
		if ($json) {
			print(json_encode($data) . PHP_EOL);
		}
	}
	else {
		print "No access token, unable to continue!" . PHP_EOL;
		exit(1);
	}


	if (($dump == false) & ($json == false)) {
		foreach ($data as $appliance) {
			If ($programStatusRaw=$appliance['state']['status']['value_raw'] != 255){

				$appliance_id=$appliance['ident']['deviceIdentLabel']['fabNumber'];
				$topicapplbase = $topicbase . $appliance_id . '/';


                                if ($appliance['state']['startTime'][0] != "0" && $appliance['state']['startTime'][1] != "0"){
                                  $starttime = date("Y-m-d") . "T" . sprintf("%'.02d:%'.02d",$appliance['state']['startTime'][0],$appliance['state']['startTime'][1]) . ":00";
				  $appliance['state']['startTime'][0] = $starttime;
                                }


				$timeleft=sprintf("%'.02d:%'.02d",$appliance['state']['remainingTime'][0],$appliance['state']['remainingTime'][1]);
				$appliance['state']['remainingTime'][0] = $timeleft;


				if ( isset($appliance['state']['elapsedTime'][0])) {
					$timerunning=sprintf("%'.02d:%'.02d",$appliance['state']['elapsedTime'][0],$appliance['state']['elapsedTime'][1]);
					$appliance['state']['elapsedTime'][0] = $timerunning;
				}


				if (! isset($appliance['state']['targetTemperature'][0]['value_localized'])){
					$appliance['state']['targetTemperature'][0]['value_localized'] = "0";
				}
				if (! isset($appliance['state']['targetTemperature'][1]['value_localized'])){
					$appliance['state']['targetTemperature'][1]['value_localized'] = "0";
				}
				if (! isset($appliance['state']['targetTemperature'][2]['value_localized'])){
					$appliance['state']['targetTemperature'][1]['value_localized'] = "0";
				}


				if (!isset($appliance['state']['temperature'][0]['value_localized'])){
					$appliance['state']['temperature'][0]['value_localized'] = "0";
				}
				if (!isset($appliance['state']['temperature'][1]['value_localized'])){
					$appliance['state']['temperature'][1]['value_localized'] = "0";
				}
				if (!isset($appliance['state']['temperature'][2]['value_localized'])){
					$appliance['state']['temperature'][2]['value_localized'] = "0";
				}



				if (! isset($appliance['state']['spinningSpeed']['value_localized'])){
					$appliance['state']['spinningSpeed']['value_localized'] = "0";
				}

				if (! isset($appliance['state']['ecoFeedback']['currentWaterConsumption']['value'])){
					$appliance['state']['ecoFeedback']['currentWaterConsumption']['value'] = "0";
				}

                                if (!isset($appliance['state']['ecoFeedback']['currentEnergyConsumption']['value'])){
					$appliance['state']['ecoFeedback']['currentEnergyConsumption']['value'] = "0";
				}


				$tosend=json_encode($appliance, JSON_UNESCAPED_UNICODE );
                                $mqtt->publish($topicapplbase . "json", $tosend);

				if($debug){
         		        	print json_encode($appliance, JSON_UNESCAPED_UNICODE) . PHP_EOL;
				}
		}
		else {

			$topicapplbase = $topicbase . $appliance_id . '/';
			$mqtt->publish($topicapplbase . "ProgramStatus", "Disconnected");
			if($debug){
				print "Appliance disconnected" . PHP_EOL;
				}
			}
		}
	}
}
?>
