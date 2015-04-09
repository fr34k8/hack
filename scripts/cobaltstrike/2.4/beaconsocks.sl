import socks.*;

# setup a portfwd...
# id, local port, remote host, remote port
sub api_beacon_pivot {
	local('$id $port $socks');
	($id, $port) = $2;

	# existing SOCKS server? no worries...
	if ($id !in %socks) {
		$socks = [new SocksProxy];
		[$socks addProxyListener: [new BeaconProxyListener: int($id), $client]];
		%socks[$id] = $socks;
	}
	else {
		# retrieve our existing SOCKS server
		$socks = %socks[$id];

		# kill the old server, we're starting a new one
		[$socks die];
	}

	# if we're supposed to stop, go ahead and do it.
	if ($port is $null) {
		[$socks killClients];
		%socks[$id] = $null;
		call_async($client, "beacon.log_write", $id, "[*] stopped SOCKS4a server\n");
		return;
	}

	# start the socks proxy server
	if (![$socks go: $port]) {
		%socks[$id] = $null;
		call_async($client, "beacon.log_write", $id, "[-] Could not start SOCKS4a server on $port $+ : " . [$socks getLastError] . "\n");
		return;
	}

	# let her rip y0.
	call_async($client, "beacon.log_write", $id, "[*] started SOCKS4a server on: $port $+ \n");
}

# setup a portfwd...
# id, local port, remote host, remote port
sub api_beacon_pivot_once {
	local('$id $port $socks');
	($id, $port) = $2;

	# existing SOCKS server? no worries...
	if ($id !in %socks) {
		$socks = [new SocksProxy];
		[$socks addProxyListener: [new BeaconProxyListener: int($id), $client]];
		%socks[$id] = $socks;
	}
	else {
		# retrieve our existing SOCKS server
		$socks = %socks[$id];
	}

	# start the socks proxy server
	if (![$socks portfwd: $port]) {
		call_async($client, "beacon.log_write", $id, "[-] Could not start SOCKS4a server on $port $+ : " . [$socks getLastError] . "\n");
	}
}
