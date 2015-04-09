# 
# Application Browser (for Cloud Strike)
#

import table.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import ui.*;

sub updateApplicationModel {
	fork({
		local('$port $row $host');
		[$model clear: 256];
		foreach $row (profiles()) {
			[$model addEntry: $row];	
		}
		[$model fireListeners];
	}, \$model, \$mclient);
}

#
# findExploits("application", "version", "", "", $always => always show exploits w/wo module)
#
sub findExploits {
	local('$handle $temp $module $app $ver $check $module $point @r $always');
	$handle = [SleepUtils getIOHandle: resource("resources/clientside.txt"), $null];
	while $temp (readln($handle)) {
		($module, $app, $ver, $check) = split('\t+', $temp);
		if ("$4 $+ *" !iswm $module && "multi/*" !iswm $module) {
			# module doesn't match our os...
		}
		else if ($always is $null && $module !in @exploits) {
			# module is not present... ignore it.
		}
		else if ($app eq $1) {
			if ($ver eq $2) {
				push(@r, $module);
			}
			else if ($2 ismatch $ver) {
				if ($1 eq "Internet Explorer") {
					if ($3 < $check) {
						push(@r, $module);
					}
				}
				else {
					$point = int(matched()[0]);
					if ($point <= int($check)) {
						push(@r, $module);
					}
				}
			}
		}
	}
        closef($handle);
	return @r;
}

sub createApplicationsBrowser {
	local('$table $model $panel $refresh $exploits $sorter $host $setup $clear $help');

	$model = [new GenericTableModel: @("external", "internal", "application", "version", "date"), "internal", 16];

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

	$table = [new ATable: $model];
	$sorter = [new TableRowSorter: $model];
        [$sorter toggleSortOrder: 1];
	[$table setRowSorter: $sorter];

	updateApplicationModel(\$model);

	[[$table getColumn: "external"] setPreferredWidth: 125];
	[[$table getColumn: "internal"] setPreferredWidth: 125];
	[$sorter setComparator: 4, {
		return convertDate($1) <=> convertDate($2);
	}];
	[$sorter setComparator: 0, &compareHosts];
	[$sorter setComparator: 1, &compareHosts];

	[$panel add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$exploits = [new JButton: "Show Exploits"];
	[$exploits addActionListener: lambda({
		local('$app $ver @exploits $all $exploit %a $temp $level $os');

		$all = [$model getSelectedValuesFromColumns: $table, @("application", "version", "level", "os")];
		foreach $temp ($all) {
			($app, $ver, $level, $os) = $temp;
			foreach $exploit (findExploits($app, $ver, $level, $os)) {
				%a[$exploit] = 1;
			}
		}

		showExploitModules(keys(%a));
	}, \$model, \$table)];

	$setup = [new JButton: "Launch Profiler"];
	[$setup addActionListener: &startProfiler];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateApplicationModel(\$model);
	}, \$model, \$setup)];

	$clear = [new JButton: "Clear"];
	[$clear addActionListener: lambda({
		thread(lambda({
			data_clear("cloudstrike.client_profiles");
			updateApplicationModel(\$model);
		}, \$model));
	}, \$model)];

	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-application-browser")];

	[$panel add: center($setup, $exploits, $refresh, $clear, $help), [BorderLayout SOUTH]];
	[$frame addTab: "Applications", $panel, $null];
}

# construct a list of client-side vulnerabilities (where they exist)
sub clientVulns {
	local('$profile @r $info $name $desc $refs $temp $app $version $exploit $level $os %seen $internal $external $key');
	foreach $profile (_profiles($1)) {
		($app, $version, $level, $os, $internal, $external) = values($profile, @('application', 'version', 'level', 'os', 'internal', 'external'));
		foreach $exploit (findExploits($app, $version, $level, $os)) {
			$temp = copy($profile);
			$info = call($mclient, "module.info", "exploit", $exploit);
			$key = "$internal $+ = $+ $external $+ =" . $info['name'];
			if ($key in %seen) {
				$temp = %seen[$key];
				$temp['module'] .= ", $exploit";
			}
			else {
				$temp['module'] = $exploit;
				$temp['name'] = $info['name'];
				$temp['info'] = replace($info['description'], "\n\\s+", "\n");
				$temp['refs'] = join(", ", map({ return join("-", $1); }, $info['references']));
				%seen[$key] = $temp;
				push(@r, $temp);
			}
		}
	}
	return @r;
}
