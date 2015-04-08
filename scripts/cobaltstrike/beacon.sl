#
# Implement the RPC extensions for Beacon
# (in theory, this API is flexible enough to support other session types... just a thought)

# read some text from a log associated with the beacon
# id, reader id 
sub api_log_read {
	local('$uid $id $blog');
	($uid, $id) = split('/', $2[0]);
	$blog  = %log[$id];
	return %(data => [$blog get: $uid]);
}

# register tab completion options from a PowerShell script
sub api_beacon_psh_tab {
	local('$bid $cmdlets');
	($bid, $cmdlets) = $2;
	%psh_tabs[$bid] = sorta(split(" ", $cmdlets));
	return %();
}

sub api_beacon_tab {
	local('$id $data $first $second @commands @o $command $space');
	@commands = @('bypassuac', 'cd', 'checkin', 'clear', 'download', 'execute', 'exit', 'getsystem', 'getuid', 'help', 'inject', 'kerberos_ticket_purge', 'kerberos_ticket_use', 'keylogger', 'kill', 'link', 'message', 'meterpreter', 'mode', 'powershell', 'powershell-import', 'ps', 'pwd', 'rev2self', 'runas', 'shell', 'sleep', 'socks', 'spawn', 'spawnto', 'steal_token', 'task', 'timestomp', 'unlink', 'upload');
	($id, $data) = $2;
	
	if ($data ismatch "(.*?)(\\s+)(.*)") {
		($first, $space, $second) = matched();
		if ($first eq "help") {
			foreach $command (@commands) {
				if ("$first $+ $space $+ $second $+ *" iswm "$first $+ $space $+ $command") {
					push(@o, "$first $+ $space $+ $command");
				}
			}
		}
		else if ($first eq "keylogger") {
			foreach $command (@("start", "stop")) {
				if ("$first $+ $space $+ $second $+ *" iswm "$first $+ $space $+ $command") {
					push(@o, "$first $+ $space $+ $command");
				}
			}
		}
		else if ($first eq "mode") {
			foreach $command (@("dns", "dns-txt", "http", "smb")) {
				if ("$first $+ $space $+ $second $+ *" iswm "$first $+ $space $+ $command") {
					push(@o, "$first $+ $space $+ $command");
				}
			}
		}
		else if ($first eq "socks") {
			foreach $command (@("stop")) {
				if ("$first $+ $space $+ $second $+ *" iswm "$first $+ $space $+ $command") {
					push(@o, "$first $+ $space $+ $command");
				}
			}
		}
		else if ($first eq "powershell" && $id in %psh_tabs && size(%psh_tabs[$id]) > 0) {
			local('$option');
			foreach $option (%psh_tabs[$id]) {
				if ("$first $+ $space $+ $second $+ *" iswm "$first $+ $space $+ $option") {
					push(@o, "$first $+ $space $+ $option");
				}
			}
		}
	}
	else {
		foreach $command (@commands) {
			if ("$data $+ *" iswm $command) {
				push(@o, $command);
			}
		}
	}

	return %(tabs => @o);
}

# write some text to a log associated with the beacon
# id, text
sub api_log_write {
	local('$id $data');
	($id, $data) = $2;
	[%log[$id] put: $data];
	return %();
}

# write to the queue for a specific beacon id 
# id, data
sub api_beacon_task {
	local('$id $data');
	if (size($2) == 3) {
		($id, $data, $MY_ADDRESS) = $2;
	}
	else {
		($id, $data) = $2;
	}
	writeb(%queue[$id], $data);
	return %();
}

# change the agent's mode.
sub api_beacon_mode {
	local('$id $mode');
	($id, $mode) = $2;
	%mode[$id] = $mode;
	return %();
}

sub api_beacon_check {
	local('$id $always $mask');
	($id, $always) = $2;

	# $always is an API option to specify whether we should skip the nonsense of
	# not providing an address to call back to.
	if ($always is $null) {
		if ($id !in %queue || %queue[$id] is $null || $MY_ADDRESS is $null) {
			return;
		}
	}

	# exfil data over DNS
	if (%mode[$id] eq "dns" || %mode[$id] eq "dns-txt") {
		$mask = 0xFFFFFFF0L;

		# do we need to send metadata?
		if ($id !in %beacons || 'user' !in %beacons[$id]) {
			$mask |= 0x1L;
		}

		# should we communicate using TXT records?
		if (%mode[$id] eq "dns-txt") {
			$mask |= 0x2L;
		}

		return $mask;
	}
	# nope, do it over HTTP.... alrighty then...
	else {
		return [graph.Route ipToLong: $MY_ADDRESS];
	}
}

# returns the queued "commands"
# id
sub api_beacon_dump {
	local('$id $data');
	($id) = $2;

	if ($id !in %queue || %queue[$id] is $null) {
		return;
	}

	# close the read end of our buffer
	closef(%queue[$id]);

	# read our buffer
	$data = readb(%queue[$id], -1);

	# kill our buffer
	closef(%queue[$id]);
	%queue[$id] = $null;
	return $data;
}

# lists all of the beacons
sub api_beacon_list {
	return map({ 
		local('$temp');
		$temp = copy($1);
		if ($temp['last'] > ticks()) {
			# time correction HACK (this is wrong, but what choice do I have
			# if the system time shifts on me?)
			$temp['last'] = $temp['last'] - ticks();
		}
		else {
			$temp['last'] = ticks() - $temp['last'];
		}
		return $temp;
	}, values(%beacons));
}

# associate some metadata with a beacon
# id, %(data ...)
sub api_beacon_register {
	local('$id $data $k $v');
	($id, $data) = $2;
	foreach $k => $v (convertAll($data)) {
		%beacons[$id][$k] = $v;
	}

	# mark a checkin time if we don't have one... necessary for beacon linking
	if ('last' !in %beacons[$id]) {
		%beacons[$id]['last'] = ticks();
	}

	#call_async($client, "db.log_event", $data['host'] . "//beacon", "received beacon from agent $id");
	return %();
}

# remove the beacon from our data structure, it'll come back if it pings again
# id
sub api_beacon_close {
	local('$id');
	($id) = $2;
	%beacons[$id] = $null;
	%queue[$id]   = $null;
	%log[$id]     = $null;
	return %();
}

# clear the queue for a beacon
# id
sub api_beacon_clear {
	local('$id');
	($id) = $2;
	%queue[$id] = $null;
	return %();
}

# initialize all of our beacon hooks
sub init_beacon_hooks {
	wait(fork({
		debug(7 | 34); # we throw exceptions here....
		global('%queue %beacons %log $MY_ADDRESS %mode %psh_tabs');
	
		%queue = ohash();
		setMissPolicy(%queue, {
			return allocate(8192);
		});

		%log = ohash();
		setMissPolicy(%log, {
			return [new armitage.ArmitageBuffer: 8192];
		});

		[$client addHook: "beacon.log_read",    &api_log_read];
		[$client addHook: "beacon.log_write",   &api_log_write];
		[$client addHook: "beacon.tabs",        &api_beacon_tab];
		[$client addHook: "beacon.task",       &api_beacon_task];
		[$client addHook: "beacon.dump",       &api_beacon_dump];
		[$client addHook: "beacon.check",      &api_beacon_check];
		[$client addHook: "beacon.list",       &api_beacon_list];
		[$client addHook: "beacon.register",   &api_beacon_register];
		[$client addHook: "beacon.remove",     &api_beacon_close];
		[$client addHook: "beacon.clear",      &api_beacon_clear];
		[$client addHook: "beacon.mode",       &api_beacon_mode];
		[$client addHook: "beacon.set_psh_functions", &api_beacon_psh_tab];
	}, \$client, $mclient => $client));
}
