import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

sub checkLicense {
	local('$today $start $left $form $life $difference');
	$today = ticks();
	$start = long([$preferences getProperty: "cobaltstrike.start.int", ""]);
	$life  = 21;

	if ($start == 0) {
		[$preferences setProperty: "cobaltstrike.start.int", $today];
		savePreferences();
		$start = $today;
	}

	$difference = ($today - $start) / (1000L * 60L * 60L * 24L);

	# And, let's talk about my demographic of users for a minute. Cobalt Strike is for
	# sale to penetration testers. You know, the people who probably got their start
	# writing cracks for software and trading them on EFNet in the early-nineties.
	#
	# I could put some sort of crazy activation scheme in here. Unfortunately, it's a 
	# requirement for some users that their pen testing tools do not leave their network.
	#
	# I could put a lot of effort into copy protection / cuffing your hands. It would
	# be useless... you'd defeat 100 hours of copy protection effort in about 5 hours.
	#
	# I'm going to focus my limited man-hours to making sure the next version is better
	# than the last for things that matter to end users.
	if ($difference > $life || ($today - $start) < 0) {
		[JOptionPane showMessageDialog: $frame, "Your Cobalt Strike trial is now expired.\nPlease purchase a license and use the\nsoftware update feature to continue.\n\nFor details, visit:\nhttp://www.advancedpentest.com/"];
		[System exit: 0];
	}
	else {
		$left = $life - $difference;
		$form = "$left day" . iff($left == 1, "", "s");
		[JOptionPane showMessageDialog: $frame, "This is a trial version of Cobalt Strike.\nYou have $form left of your trial.\n\nIf you purchased Cobalt Strike. Run the\nUpdate program and enter your license."];
	}
}

sub isPaid {
	return $null;
}

sub checkVersion {
	local('$version $required $raw');
	$required = "4.3.0-release";
	$raw = call($client, "core.version");
	$version = $raw['version'];
	if ($version ne $required && 1 == 0) {
		showErrorAndQuit("This is the trial version of Cobalt Strike. You may use it with 
the stock Metasploit Framework $required package.

You are using:
<html><body><b>Metasploit Framework $version $+ </b></body></html>

Licensed Cobalt Strike users have access to the latest
release of Cobalt Strike. These updates are usually compatible
with the latest changes in the Metasploit Framework. If you're
a licensed user, use the update program included with Cobalt
Strike to get the latest release.

If you're a trial user, please reinstall the Metasploit Framework
and do not run msfupdate.");
	}
}

sub getLicenseKey {
	return $null;
}
