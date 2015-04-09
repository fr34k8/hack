#
# Cloud Strike User Interface Framework
#

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.filechooser.*;

import java.awt.*;
import java.awt.event.*;

import java.io.*;

import ui.*;

# This framework is organized into choosers. These choosers do the following:
# - create a row of UI elements suitable for use with the matrix() layout function
# - populate an @functions array with a function for populating a %hash with the value of the chooser
# - accept a %hash and initialize their value from it.

sub populateData {
	local('$function');
	foreach $function ($1) {
		[$function: $2];
	}
	return $2;
}

# creates a button that fires a callback with a %hash containing the values of this form...
sub ui:action {
	local('$button');
	$button = invoke(&ui:action_noclose, @_);
	[$button addActionListener: lambda({
		# don't close the dialog if the user held down shift.
		if (!isShift($1)) {
			[$d setVisible: 0];
		}
	}, $d => $4)];
	return $button;
}

# creates a button that fires a callback with a %hash containing the values of this form...
sub ui:action_noclose {
	local('$t @f %o $c $d $button');
	($t, @f, %o, $d, $c) = @_;

	$button = [new JButton: $t];
	[$button addActionListener: lambda({
		# disable the button... prevents user from clicking a million times
		[[$1 getSource] setEnabled: $null];

		thread(lambda({
			local('$ex');
			populateData(@f, %o);

			# special case... set EXE::Custom in an async way please!
			if (%o['listener'] eq "use custom executable...") {
				openFile($this, $title => "Select executable");
				yield;
				%o['EXE::Custom'] = $1;
			}

			[$c: %o, $e];

			# re-enable the button
			dispatchEvent(lambda({
				[$s setEnabled: 1];
			}, \$s));
		}, \@f, \%o, \$c, $e => $1, $s => [$1 getSource]));
	}, \@f, \%o, \$c, \$d)];

	return $button;
}

# @(label, field, button) := fileChooser("text", "key", @functions, %original, "upload?", text cols)
sub ui:file {
	local('$label $text $button');
	($label, $text) = invoke(&ui:text, @_);
	$button = [new JButton: [[FileSystemView getFileSystemView] getSystemIcon: [new File: "."]]];

	[$button addActionListener: lambda({
		openFile(lambda({
			[$text setText: $1];
		}, \$text), $title => "Choose file");
	}, \$text)];

	# add another function... check if we're in teaming mode and if we are, upload
	# this file that was selected.
	if ($5) {
		push($3, lambda({
			if ($client !is $mclient && [$text getText] ne "") {
				$1[$key] = uploadFile([$text getText]);
			}
		}, \$text, $key => $2));
	}

	return @($label, $text, $button);
}

sub ui:text {
	local('$t $k @f %o $6');
	($t, $k, @f, %o) = @_;

	local('$label $text');

	if ([$t endsWith: " *"]) {
		$label = [new JLabel: substr($t, 0, -2)];
		[$label setForeground: [Color decode: '#004A80']];
		#[$label setForeground: [Color decode: '#36769C']];
	}
	else {
		$label = [new JLabel: $t];
	}
	$text = [new ATextField: iff($6 is $null, 20, $6)];

	# update the value of this field...
	if ($k in %o) {
		[$text setText: %o[$k]];
	}

	# push an updater function on to the array
	push(@f, lambda({
		if ([$text getText] eq "") {
			$1[$key] = $null;
		}
		else {
			$1[$key] = [$text getText];
		}
	}, \$text, $key => $k));

	return @($label, $text, [new JPanel]);
}

sub ui:text_big {
	local('$t $k @f %o $6');
	($t, $k, @f, %o) = @_;

	local('$label $text');
	$label = [new JLabel: $t];
	$text = [new JTextArea];
	[$text setRows: 3];

	if ($6 !is $null) {
		[$text setColumns: $6];
	}

	[$text setLineWrap: 1];
	[$text setWrapStyleWord: 1];

	# update the value of this field...
	if ($k in %o) {
		[$text setText: %o[$k]];
	}

	# push an updater function on to the array
	push(@f, lambda({
		if ([$text getText] eq "") {
			$1[$key] = $null;
		}
		else {
			$1[$key] = [$text getText];
		}
	}, \$text, $key => $k));

	return @($label, [new JScrollPane: $text], [new JPanel]);
}

# $5 = items to choose from!
sub ui:combobox {
	local('$t $k @f %o');
	($t, $k, @f, %o) = @_;

	local('$label $combobox');
	$label = [new JLabel: $t];
	$combobox = [new JComboBox: cast($5, ^Object)];
	[$combobox setPreferredSize: [new Dimension: 240, 0]];

	# 1. set one of them as selected...
	if ($k in %o) {
		[$combobox setSelectedItem: %o[$k]];
	}
		
	# 2. push the value getting function
	push(@f, lambda({
		$1[$key] = [$combobox getSelectedItem];
	}, \$combobox, $key => $k));

	return @($label, $combobox, [new JPanel]);
}

sub ui:encoders {
	local('$t $k @f %o @encoders');
	($t, $k, @f, %o) = @_;

	@encoders = @("generic/none", "x86/call4_dword_xor", "x86/countdown", "x86/fnstenv_mov", "x86/jmp_call_additive", "x86/shikata_ga_nai");
	return ui:combobox($t, $k, @f, %o, @encoders);
}

sub ui:migrate {
	local('$t $k @f %o @procs');
	($t, $k, @f, %o) = @_;

	@procs = split(" ", "calc.exe charmap.exe cleanmgr.exe cliconfg.exe cmd.exe control.exe cscript.exe dcomcnfg.exe dllhost.exe dvdplay.exe dxdiag.exe fontview.exe ftp.exe gpupdate.exe help.exe iexpress.exe mmc.exe msiexec.exe mspaint.exe mstsc.exe notepad.exe perfmon.exe regedt32.exe rundll32.exe runonce.exe sethc.exe svchost.exe systray.exe write.exe wscript.exe");
	if ($k !in %o) {
		%o[$k] = "notepad.exe";
	}
	return ui:combobox($t, $k, @f, %o, @procs);
}

# psexec listener bishes...
sub ui:listener_psexec {
	local('$t $k @f %o $label $combobox $add');
	($t, $k, @f, %o) = @_;
	($label, $combobox, $add) = ui:listener($t, $k, @f, %o, "*windows*");

	dispatchEvent(lambda({
		[$combobox addItem: "meterpreter (connect to target)"];
		[$combobox addItem: "beacon (connect to target)"];
		[$combobox addItem: "shell (connect to target)"];
		[$combobox addItem: "use custom executable..."];
	}, \$combobox));

	return @($label, $combobox, $add);
}

# psexec listener bishes...
sub ui:listener_psexec2 {
	local('$t $k @f %o $label $combobox $add');
	($t, $k, @f, %o) = @_;
	($label, $combobox, $add) = ui:listener($t, $k, @f, %o, "*windows*");

	dispatchEvent(lambda({
		[$combobox addItem: "meterpreter (connect to target)"];
		[$combobox addItem: "beacon (connect to target)"];
		[$combobox addItem: "shell (connect to target)"];
	}, \$combobox));

	return @($label, $combobox, $add);
}

# psexec listener bishes...
sub ui:listener_psexec_token {
	local('$t $k @f %o $label $combobox $add');
	($t, $k, @f, %o) = @_;
	($label, $combobox, $add) = ui:listener($t, $k, @f, %o, "*windows*");

	dispatchEvent(lambda({
		[$combobox addItem: "use custom executable..."];
	}, \$combobox));

	return @($label, $combobox, $add);
}

sub ui:stages {
	local('$t $k @f %o');
	($t, $k, @f, %o) = @_;

	local('$combobox $label');

	($label, $combobox) = ui:combobox($t, $k, @f, %o, @());

	[lambda({
		local('@stages');
		call_async_callback($mclient, "beacon.list_stages", $this);
		yield;
		@stages = convertAll($1); 
		
		# from the Swing UI thread--add the stages to our combobox
		dispatchEvent(lambda({
			map(lambda({ [$combobox addItem: $1]; }, \$combobox), @stages);
		}, \@stages, \$combobox));
	}, \$combobox)];

	return @($label, $combobox, [new JPanel]);
}

# $5 = *filter*
sub ui:listener {
	local('$t $k @f %o');
	($t, $k, @f, %o) = @_;

	local('$combobox $label $add');

	($label, $combobox) = ui:combobox($t, $k, @f, %o, @());

	thread(lambda({
		local('@listeners %l $k $v $listener');
		%l = ohash();
		@listeners = filter(lambda({ return iff($f iswm $1['payload'], $1); }, \$f), listeners_all());
		foreach $listener (@listeners) {
			$k = $listener['name'];
			$v = $listener['payload'];
			%l[$k] = $v;
		}

		# from the Swing UI thread--add the listeners to our combobox
		dispatchEvent(lambda({
			local('$k $v');
			foreach $k => $v (%l) {
				[$combobox addItem: $k];
				if ($v eq "windows/beacon_dns/reverse_http") {
					[$combobox addItem: "$k (DNS)"];
				}
			}
		}, \%l, \$combobox));
	}, \$combobox, $f => $5));

	$add = [new JButton: "Add"];

	[$add addActionListener: lambda({
		newListener($null, $null, \$filter, $callback => lambda({
			[$combobox addItem: $1];
			if ($2 eq "windows/beacon_dns/reverse_http") {
				[$combobox addItem: "$1 (DNS)"];
			}
			[$combobox setSelectedItem: $1];
		}, \$combobox));
	}, \$combobox, $filter => $5)];

	return @($label, $combobox, $add);
}

# $5 = *filter*
sub ui:interface {
	local('$t $k @f %o');
	($t, $k, @f, %o) = @_;

	local('$combobox $label $add');

	($label, $combobox) = ui:combobox($t, $k, @f, %o, @());

	[lambda({
		local('@interfaces');

		# retrieve a list of our interfaces
		call_async_callback($mclient, "cloudstrike.list_taps", $this);
		yield;
		@interfaces = convertAll($1); 

		# filter out any interfaces that are in use
		@interfaces = filter({ return iff($1['client'] eq "not connected", $1); }, @interfaces);

		# grab just the interface names...
		@interfaces = map({ return $1['interface']; }, @interfaces);

		# from the Swing UI thread--add the interfaces to our combobox
		dispatchEvent(lambda({
			local('$interface');
			foreach $interface (@interfaces) {
				[$combobox addItem: $interface];
			}
		}, \@interfaces, \$combobox));
	}, \$combobox)];

	$add = [new JButton: "Add"];

	[$add addActionListener: lambda({
		addInterface(lambda({
			if ($1 !is $null && $1['status'] eq 'success') {
				[$combobox addItem: $2];
				[$combobox setSelectedItem: $2];
			}
			else {
				showError($1['status']);
			}
		}, \$combobox));
	}, \$combobox)];

	return @($label, $combobox, $add);
}

sub ui:workspace {
	local('$t $k @f %o');
	($t, $k, @f, %o) = @_;

	local('@workspaces $combobox $label $add $workspaces');

	$workspaces = workspaces();
	@workspaces = map({ return $1["name"]; }, $workspaces);
	add(@workspaces, "All Hosts", 0);

	($label, $combobox) = ui:combobox($t, $k, @f, %o, @workspaces);

	push(@f, lambda({
		local('$sel $workspace');
		$sel = [$combobox getSelectedItem];

		if ($sel eq "All Hosts") {
			$1[$key] = %();
		}
		else {
			foreach $workspace ($workspaces) {
				if ($workspace['name'] eq $sel) {
					$1[$key] = $workspace;
					return;
				}
			}
		}
		$1[$key] = %();
	}, \$combobox, $key => $k, \$workspaces));

	return @($label, $combobox, [new JPanel]);
}

# @(label, field, button) := fileChooser("text", "key", @functions, %original)
sub ui:attack {
	local('$label $text $button');
	($label, $text) = invoke(&ui:text, @_);
	$button = [new JButton: "..."];

	[$button addActionListener: lambda({
		chooseClientSide(lambda({
			[$text setText: $1];
		}, \$text));
	}, \$text)];

	return @($label, $text, $button);
}

# @(label, field, button) := fileChooser("text", "key", @functions, %original)
sub ui:mailserver {
	local('$label $text $button');
	($label, $text) = invoke(&ui:text, @_);
	$button = [new JButton: "..."];

	[$button addActionListener: lambda({
		setupMailServer(lambda({
			[$text setText: $1];
		}, \$text), [$text getText]);
	}, \$text)];

	return @($label, $text, $button);
}

# @(label, field, button) := fileChooser("text", "key", @functions, %original)
sub ui:site {
	local('$label $text $button');
	($label, $text) = invoke(&ui:text, @_);
	$button = [new JButton: "..."];

	[$button addActionListener: lambda({
		chooseSite(lambda({
			[$text setText: $1 . '?id=%TOKEN%'];
		}, \$text));
	}, \$text)];

	return @($label, $text, $button);
}

# this item is unique because it does not return a row suitable for matrix()
sub ui:checkbox {
	local('$t $k @f %o');
	($t, $k, @f, %o) = @_;

	local('$checkbox');
	$checkbox = [new JCheckBox: $t];

	# update the value of this field...
	if ($k in %o && %o[$k] eq '1') {
		[$checkbox setSelected: 1];
	}
	else {
		[$checkbox setSelected: 0];
	}

	# push an updater function on to the array
	push(@f, lambda({
		$1[$key] = iff([$checkbox isSelected], '1', $null);
	}, \$checkbox, $key => $k));

	return $checkbox;
}

sub rowLayout {
	local('$a $label $component $add');
        ($label, $component, $add) = $1;

        $a = [new JPanel];
        [$a setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];
        [$a setLayout: [new BorderLayout: 5, 5]];
        [$a add: $label, [BorderLayout WEST]];
        [$a add: $component, [BorderLayout CENTER]];
        [$a add: $add, [BorderLayout EAST]];
	return $a;
}

# matrixLayout($panel, @(@row1, @row2, @row3), #cols)
sub matrixLayout {
	local('$layout $hgroup $pgroup $row $vgroup $x $item');
	$layout = [new GroupLayout: $1];
	[$1 setLayout: $layout];
	[$layout setAutoCreateGaps: 1];
	[$layout setAutoCreateContainerGaps: 1];

	# horizontal stuff
	$hgroup = [$layout createSequentialGroup];

		for ($x = 0; $x < $3; $x++) {
			$pgroup = [$layout createParallelGroup];
			foreach $row ($2) {
				if ($row[$x] is $null) {
					println("Row: $row has a null value!");
				}
				[$pgroup addComponent: $row[$x]];
			}
			[$hgroup addGroup: $pgroup];
		}

		[$layout setHorizontalGroup: $hgroup];


	$vgroup = [$layout createSequentialGroup];

		foreach $row ($2) {
			$pgroup = [$layout createParallelGroup: [GroupLayout$Alignment BASELINE]];
			foreach $item ($row) {
				[$pgroup addComponent: $item];
			}
			[$vgroup addGroup: $pgroup];
		}

		[$layout setVerticalGroup: $vgroup];
}

sub description {
	local('$textarea $scroll');
	$textarea = [new JEditorPane];
	[$textarea setContentType: "text/html"];
	[$textarea setText: [join(" ", split('[\\n\\s]+', $1)) trim]];
	[$textarea setEditable: 0];
	[$textarea setOpaque: 1];
	[$textarea setCaretPosition: 0];
	[$textarea setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];

	$scroll = [new JScrollPane: $textarea];
	[$scroll setPreferredSize: [new Dimension: 0, 48]];
	[$scroll setBorder: [BorderFactory createEmptyBorder: 3, 3, 3, 3]];

	return $scroll;
}
