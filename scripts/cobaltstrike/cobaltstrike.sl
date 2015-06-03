#
# Scripting Functions for Cobalt Strike (yes, it's coming *pHEAR*)
#

# open_beacon_console: [beacon id], "title", [host - if known]
#	interact with a beacon
sub open_beacon_console {
	_call_async_("&createBeaconConsole", $1, $2, $3);
}

# open_beacon_browser:
#	pop open the Beacons tab.
sub open_beacon_browser {
	_call_async_("&createBeaconBrowser");
}

#
# the beginnings of a Beacon API
#

# id, command + args
sub bshell {
	local('$id $len');
	$len  = strlen($2);

	# task the agent(s)...
	call_async("beacon.task", $1, pack("IIZ $+ $len", 0x02, $len, $2));
	call_async("beacon.log_write", $1, "[*] Tasked beacon to run: $2 $+ \n");
}

# id, file
sub bupload {
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
	call_async("beacon.task", $1, pack("IIIZ $+ $nlen $+ Z $+ $dlen", 0x0A, $len, $nlen, $name, $data)); 
	call_async("beacon.log_write", $1, "[*] Tasked beacon to upload $2 $+ \n");
}

# @beacons = beacons();
sub beacons {
	return call("beacon.list");
}

# change the working directory of the beacon
sub bcd {
	local('$id $len');
	$len = strlen($2);
	call_async("beacon.task", $1, pack("IIZ $+ $len", 0x05, $len, $2));
	call_async("beacon.log_write", $1, "[*] cd $2\n");
}

sub __bstring {
	local('$len');
	$len = strlen($1);
	return pack("IZ $+ $len", $len, $1);
}

# btimestomp($id, $src, $dst)
sub btimestomp {
	local('$id $a $b $c');

	$a = __bstring($3);
	$b = __bstring($2);
	$c = strlen($a . $b);

	# task beacon to timestomp $2 and $3
	call_async("beacon.task", $1, pack("IIZ $+ $c", 0x1D, $c, $a . $b));
	call_async("beacon.log_write", $1, "[*] Tasked beacon to timestomp $2 to $3 $+ \n");
}

# bsleep($bid, ms, jitter)
sub bsleep {
	local('$3');
	if ($2 > 0) {
		call_async("beacon.task", $1, pack("IIII", 0x04, 8, $2 * 1000, $3));
		if ($3 == 0) {
			call_async("beacon.log_write", $1, "[*] Tasked beacon to sleep for $2 $+ s\n");
		}
		else {
			call_async("beacon.log_write", $1, "[*] Tasked beacon to sleep for $2 $+ s ( $+ $3 $+ % jitter)\n");
		}
	}
	else {
		call_async("beacon.task", $1, pack("IIII", 0x04, 8, 100, 90), $null);
		call_async("beacon.log_write", $1, "[*] Tasked beacon to become interactive\n");
	}
}

# bnote($bid, whatever)
# associate a note with the beacon
sub bnote {
	call_async("beacon.register", $1, %(id => $1, note => "$2"));
}

# bdata($bid);
# return the data associated with the beacon
sub bdata {
	local('$entry');
	foreach $entry (beacons()) {
		if ($entry['id'] eq $1) {
			return $entry;
		}
	}
	return %();
}

# binfo($bid, "key")
# return information about the beacon
sub binfo {
	return bdata($1)[$2];
}
