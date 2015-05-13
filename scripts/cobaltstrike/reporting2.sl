#
# Armitage Reporting... (well, sorta... not going to generate PDFs any time soon :))
#

import java.io.*;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;

import report.Reporter;

import graph.Route;

sub fixData {
	if (-ishash $1 || -isarray $1) {
		local('$key $value');
		foreach $key => $value ($1) {
			#if ($key eq "data" || $key eq "info" || $key eq "user" || $key eq "pass" || $key eq "site") {
			if ($key eq "data" || $key eq "user" || $key eq "pass" || $key eq "site") {
				local('$s');
				$s = split("", $value);
				map({ $1 = strrep($1, '&', '&amp;', '<', '&lt;', '>', '&gt;'); }, $s);

				if ($2 eq 'PDF') {
					$value = join('&#x200B;', $s);
				}
				else {
					$value = join('', $s);
				}

				$value = replace($value, '\\P{Print}', ' ');
			}
			else {
				fixData($value, $2);
			}
		}
	}
	else {
		$1 = replace(strrep($1, '&', '&amp;', '<', '&lt;', '>', '&gt;'), '\\P{Print}', ' ');
	}
}

sub combineFields {
	local('$dst $new $field $key %combined $entry %r');

	if ($4 is $null) {
		$1[$3] = addAll($1[$3], $2[$3]);
	}
	else {
		# grab everything from our destination and process it...
		foreach $entry ($1[$3]) {
			$key = join("!", values($entry, $4));
			if ($key !in %r) {
				%r[$key] = $entry;
			}
			else if (%r[$key]['updated_at'] < $entry['updated_at']) {
				%r[$key] = $entry;
			}
		}

		# grab everything from our other value and process it...
		foreach $entry ($2[$3]) {
			$key = join("!", values($entry, $4));

			if ($key !in %r) {
				%r[$key] = $entry;
			}
			else if (%r[$key]['updated_at'] < $entry['updated_at']) {
				%r[$key] = $entry;
			}
		}

		$1[$3] = values(%r);
	}
}

sub combineResults {
	# shortcut the whole merge process...
	if (size($1) == 0) {
		return $2;
	}

	# ok, it's time to merge everything else...

	combineFields($1, $2, 'applications', @('application', 'external', 'internal', 'created_at', 'os', 'version'));
	combineFields($1, $2, 'client_vulns', @('os', 'application', 'module', 'external', 'version', 'info', 'created_at', 'internal', 'name', 'token', 'refs'));
	combineFields($1, $2, 'creds',        @('user', 'pass', 'host', 'port'));
	combineFields($1, $2, 'hosts',        @('address'));
	combineFields($1, $2, 'loots',        @('path', 'updated_at'));
	combineFields($1, $2, 'services',     @('host', 'port'));
	combineFields($1, $2, 'sessions',     @('id', 'local_id', 'via_payload', 'last_seen'));
	combineFields($1, $2, 'spearphishes', @('server', 'time', 'token'));
	combineFields($1, $2, 'timeline',     @('id', 'info', 'created_at'));
	combineFields($1, $2, 'vulns',        @('port', 'host', 'vuln_attempt_count', 'created_at', 'vid'));
	combineFields($1, $2, 'webkeys',      @('data', 'token', 'created_at'));
	combineFields($1, $2, 'weblog',       @('created_at', 'token', 'host', 'uri', 'method', 'size', 'handler'));

	return $1;
}

sub dumpReport {
	use(^Reporter);
	local('%data $progress $desc $aclient $total');

	if ($file !is $null) {
		$progress = [new javax.swing.ProgressMonitor: $null, "Exporting Data", "Querying Database...", 0, 100];
		sleep(500);

		# export all of our client data
		foreach $desc => $aclient (convertAll([$__frame__ getClients])) {
			%data = combineResults(%data, queryData($aclient, $options['workspace'], $desc, \$progress));
			$total += 1;
			sleep(100);
		}

		# fix our data... (don't waste our time if we're generating a report for a single team server)
		if ($total >= 1) {
			%data['hosts']       = fixHosts(%data['hosts']);
			%data['vulns']       = sort({ return [graph.Route ipToLong: $1['host']] <=> [graph.Route ipToLong: $2['host']]; }, %data['vulns']);
			%data['services']    = sort({ return $1['port'] <=> $2['port']; }, %data['services']);
			%data['sessions']    = sort({ return $1['opened_at'] <=> $2['opened_at']; }, %data['sessions']);
			%data['creds']       = sort({ return lc($1['user']) cmp lc($2['user']); }, %data['creds']);
		}

		# the user wants emails masked... 
		if ($options['maskemail']) {
			# the report manages this logic.
		}

		# the user wants passwords masked...
		if ($options['maskpass']) {
			[$progress setNote: "Masking passwords"];
			local('$entry');
			foreach $entry (%data['creds']) {
				($user, $host) = split('@', $entry['to']);
				if (isPassword($entry['ptype'])) {
					$entry['pass'] = "*" x strlen($entry['pass']);
				}
				else if (isHash($entry['ptype'], $entry['pass'])) {
					$entry['pass'] = tr($entry['pass'], 'a-zA-Z0-9', '*')
				}
				else if (isSSHKey($entry['ptype'])) {
					$entry['pass'] = 'SSH Key: ' . unpack("H*", digest($entry['pass'], "MD5"))[0];
				}
			}
		}

		# generate the report y0
		fork({
			[$progress setNote: "Generating " . $options['format'] . " Output"];
			fixData(%data, $options['format']);
			generate($options['template'], "$file", $options['format'], $preferences, %data, $options);
			[$progress close];
			showError("Report saved");
		}, \$progress, \%data, \$options, \$__frame__, \$file, \$preferences);
	}
}

sub generateReport {
	local('$dialog %options @functions $a $export $2 $mask');

	$dialog = dialog("Export Report", 320, 200);
	%options = $1;

        # the meat of the form...
        $a = [new JPanel];
	if ('workspace' in $1) {
		matrixLayout($a, @(
			ui:text(      "Short Title:", "title_short", @functions, %options),
			ui:text(      "Long Title:" , "title_long",  @functions, %options),
			ui:text_big(  "Description:", "description", @functions, %options),
			ui:combobox(  "Output:", "format", @functions, %options, @("PDF", "MS Word"))
		), 3);
	}
	else {
		matrixLayout($a, @(
			ui:workspace( "Workspace:",   "workspace",   @functions, %options),
			ui:text(      "Short Title:", "title_short", @functions, %options),
			ui:text(      "Long Title:" , "title_long",  @functions, %options),
			ui:text_big(  "Description:", "description", @functions, %options),
			ui:combobox(  "Output:", "format", @functions, %options, @("PDF", "MS Word"))
		), 3);
	}

	$export = ui:action("Export", @functions, %options, $dialog, {
		saveFile2(lambda({
			fork(&dumpReport, \$options, \$__frame__, \@exploits, \$preferences, \$mclient, $file => $1);
		}, $options => $1), $sel => $1['file'] . iff($1['format'] eq "PDF", '.pdf', '.docx'));
	});

	if ($mask eq "email") {
		$mask = ui:checkbox("Mask email addresses", "maskemail", @functions, %options);
		[$dialog add: stack($a, $mask), [BorderLayout CENTER]];
	}
	else if ($mask eq "creds") {
		$mask = ui:checkbox("Mask passwords", "maskpass", @functions, %options);
		[$dialog add: stack($a, $mask), [BorderLayout CENTER]];
	}
	else {
		[$dialog add: $a, [BorderLayout CENTER]];
	}
	[$dialog add: center($export), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
	[$dialog show];
}

sub generateActivityReport {
	local('%options');

	%options['title_short'] = "Activity Report";
	%options['title_long']  = "Activity Report";
	%options['description'] = "This report shows a timeline of this penetration test.";
	%options['file']        = 'activity_report';
	%options['template']    = 'templates/activity.rpt';
	%options['workspace']   = %(session => 1);
	generateReport(%options);
}

sub generateClientReport {
	local('%options');

	%options['title_short'] = "Client-side Vulnerability Report";
	%options['title_long']  = "Client-side Vulnerability Report";
	%options['description'] = "This report shows potential client application vulnerabilities found during this penetration test";
	%options['file']        = 'client_vuln_report';
	%options['template']    = 'templates/client_vulns.rpt';
	%options['workspace']   = %(session => 1);
	generateReport(%options);
}

sub generateHostsReport {
	local('%options');

	%options['title_short'] = "Hosts Report";
	%options['title_long']  = "Hosts Report";
	%options['description'] = "This report shows host information gathered during this penetration test.";
	%options['file']        = 'hosts_report';
	%options['template']    = 'templates/hosts.rpt';
	generateReport(%options, $mask => "creds");
}

sub generateSocialReport {
	local('%options');

	%options['title_short'] = "Social Engineering Report";
	%options['title_long']  = "Social Engineering Report";
	%options['description'] = "This report documents the social engineering portion of this penetration test.";
	%options['file']        = 'social_engineering_report';
	%options['template']    = 'templates/social.rpt';
	%options['workspace']   = %(session => 1);
	generateReport(%options, $mask => "email");
}

sub generateVulnerabilityReport {
	local('%options');

	%options['title_short'] = "Vulnerability Report";
	%options['title_long']  = "Vulnerability Report";
	%options['description'] = "This report shows vulnerabilities found during this penetration test.";
	%options['file']        = 'vulnerability_report';
	%options['template']    = 'templates/vulns.rpt';
	generateReport(%options);
}
