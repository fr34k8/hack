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

import armitage.*;

sub updateSiteModelAll {
	fork({
		[$model clear: 16];
		local('$desc $aclient @sites $site $host');
		foreach $desc => $aclient (convertAll([$__frame__ getClients])) {
			$host = call($aclient, "armitage.my_ip")['result'];
			@sites = call($aclient, "cloudstrike.list_sites");
			foreach $site (@sites) {
				$site['Host'] = $host;
				[$model addEntry: $site];
			}
		}
		[$model fireListeners];
	}, \$model, \$__frame__);
}

sub updateSiteModel {
	fork({
		[$model clear: 16];
		local('@sites $site');
		@sites = call($mclient, "cloudstrike.list_sites");
		foreach $site (@sites) {
			[$model addEntry: $site];
		}
		[$model fireListeners];
	}, \$model, \$mclient);
}

sub chooseSite {
	local('$dialog $table $model $choose');
	$dialog = dialog("Sites", 640, 200);
	[$dialog setLayout: [new BorderLayout]];

	# create a table..
	($table, $model) = setupTable("URI", @('Host', 'URI', 'Port', 'Type', 'Description'), @());
	updateSiteModelAll(\$model);

	# setup column widths..
	setTableColumnWidths($table, %(Host => 125, URI => 125, Port => 60, Type  => 60, Description => 250));

	# buttons
	$choose = [new JButton: "Choose"];
	[$choose addActionListener: lambda({
		local('$uri $port $url $host');
		$uri = [$model getSelectedValue: $table];
		$port = [$model getSelectedValueFromColumn: $table, "Port"];
		$host = [$model getSelectedValueFromColumn: $table, "Host"];
		$url  = "http:// $+ $host $+ : $+ $port $+ $uri";
		[$callback: $url];
		[$dialog setVisible: 0];
	}, \$table, \$model, $callback => $1, \$dialog)];

	# setup the dialog...
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];
	[$dialog add: center($choose), [BorderLayout SOUTH]];

	[$dialog show];
	[$dialog setVisible: 1];
}

sub manageSites {
	local('$dialog $table $model $panel $south $kill $copy $refresh $help');
	$dialog = [new JPanel];
	[$dialog setLayout: [new BorderLayout]];

	# create a table..
	($table, $model) = setupTable("URI", @('URI', 'Port', 'Type', 'Description'), @());
	updateSiteModel(\$model);

	# allow us to select multiple sites...
	dispatchEvent(lambda({
		[[$table getSelectionModel] setSelectionMode: [ListSelectionModel MULTIPLE_INTERVAL_SELECTION]];
	}, \$table));

	setTableColumnWidths($table, %(URI => 125, Port => 60, Type  => 60, Description => 250));

	# buttons
	$kill    = [new JButton: "Kill"];
	$copy    = [new JButton: "Copy URL"];
	$refresh = [new JButton: "Refresh"];	
	$help    = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-manage-sites")];

	# setup the buttons...
	[$refresh addActionListener: lambda({
		updateSiteModel(\$model);
	}, \$model)];

	[$copy addActionListener: lambda({
		local('$uri $port $url $desc');
		$uri = [$model getSelectedValue: $table];
		$port = [$model getSelectedValueFromColumn: $table, "Port"];
		$desc = [$model getSelectedValueFromColumn: $table, "Description"];
		$url  = "http:// $+ $MY_ADDRESS $+ : $+ $port $+ $uri";
		if ($desc eq "PowerShell Web Delivery") {
			[addToClipboard([common.CommonUtils PowerShellOneLiner: $url])];
		}
		else {
			[addToClipboard($url)];
		}
	}, \$table, \$model)];

	[$kill addActionListener: lambda({
		local('$all');
		$all = [$model getSelectedValuesFromColumns: $table, @("URI", "Port")];
		[lambda({
			local('$URI $port $item');
			foreach $item ($all) {
				($URI, $port) = $item;
				call_async_callback($mclient, "cloudstrike.kill_site", $this, $port, $URI);
				yield;
			}
			updateSiteModel(\$model);
		}, \$all, \$model)];
	}, \$table, \$model)];

	# setup the dialog...
	[$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];
	[$dialog add: center($copy, $refresh, $kill, $help), [BorderLayout SOUTH]];

	[$frame addTab: "Sites", $dialog, $null];
	#[$dialog show];
}

sub fixURIOption {
	local('$path');
	$path = $1['URIPATH'] . "";
	if (![$path endsWith: "/"] && '.' !isin $path) {
		$1['URIPATH'] .= '/';
	}
};
	
# start the system profiler
sub startProfiler {
	local('$dialog %options @functions $a $start $help $b');

        $dialog = dialog("System Profiler", 640, 480);

        # pre-set some of the options
	%options['Port']        = '80';
	%options['URIPATH']     = '/';
	%options['Java']        = 1;

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text("Local URI: *",    "URIPATH",  @functions, %options),
		ui:text("Local Port: *",   "Port",     @functions, %options),
		ui:text("Redirect URL:", "RedirectURL", @functions, %options),
	), 3);

	$b = ui:checkbox("Use Java Applet to get information", "Java", @functions, %options);

	# add a slash to the end of the URI always.
	push(@functions, &fixURIOption);

	# buttons?
	$help  = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-system-profiler")];

	$start = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		thread(lambda({ 
			[$dialog setVisible: 0];

			# make sure this is a string.
			if (%options['Java']) {
				%options['Java'] = "true";
			}
			else {
				%options['Java'] = "false";
			}

			local('$status');
			if (%options['RedirectURL'] ne "") {
				call_async_callback($mclient, "cloudstrike.start_profiler", $this, %options['Port'], %options['URIPATH'], %options['RedirectURL'], "System Profiler. Redirects to " . %options['RedirectURL'], %options['Java']);
				yield;
				$status = convertAll($1); 
			}
			else {
				call_async_callback($mclient, "cloudstrike.start_profiler", $this, %options['Port'], %options['URIPATH'], $null, "System Profiler", %options['Java']);
				yield;
				$status = convertAll($1); 
			}

			if ($status['status'] eq "success") {
				elog("started system profiler @ http:// $+ $MY_ADDRESS $+ :" . %options["Port"] . %options["URIPATH"]);
				startedWebService("system profiler", "http:// $+ $MY_ADDRESS $+ :" . %options["Port"] . %options["URIPATH"]);
			}
			else {
				[$dialog setVisible: 1];
				showError("Unable to start profiler:\n" . $status['status']);
			}
		}, %options => $1, \$dialog));
	}, \$dialog));

        # set up the dialog.
	[$dialog add: description("The system profiler is a client-side reconaissance tool. It finds common applications (with version numbers) used by the user."), [BorderLayout NORTH]];
	[$dialog add: stack($a, $b), [BorderLayout CENTER]];
	[$dialog add: center($start, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
	[$dialog show];
}

sub profiles {
	return _profiles($mclient);
}

sub _profiles {
	return values(_data_list($1, "cloudstrike.client_profiles"));
}

sub startedWebService {
	local('$dialog $label $text $close');
	$dialog = dialog("Success", 240, 120);
	[$dialog setLayout: [new BorderLayout]];

	$label = [new JLabel: "<html>Started service: $1 $+ <br />" .
	     "Copy and paste this URL to access it</html>"];

	$text = [new ATextField: "$2", 20];
	$close = [new JButton: "Ok"];
	[$close addActionListener: lambda({
		[$dialog setVisible: 0];
	}, \$dialog)];

	[$dialog add: wrapComponent($label, 5), [BorderLayout NORTH]];
	[$dialog add: wrapComponent($text, 5), [BorderLayout CENTER]];
	[$dialog add: center($close), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog show];
	[$dialog setVisible: 1];
}

sub setupWeblogStyle {
        this('$style');
        if ($style is $null) {
                local('$handle');
                $handle = [SleepUtils getIOHandle: resource("resources/weblog.style"), $null];
                $style = join("\n", readAll($handle));
                closef($handle);
        }
        [$1 setStyle: $style];
}

sub createWebLogTab {
        this('$console $client');

	if ($client is $null && $console is $null) {
		$console = [new ActivityConsole: $preferences];
		$client = [new ConsoleClient: $console, $mclient, "cloudstrike.web_poll", $null, $null, "", $null];
		setupWeblogStyle($console);
		logCheck($console, "all", "weblog");
		[$client setEcho: $null];
		[$console updatePrompt: "> "];
        }
	else {
		[$console updateProperties: $preferences];
        }

	[$frame addTab: "Web Log", $console, $null];
}

