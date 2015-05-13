import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

sub checkLicense {
	# hah... this is the paid version, we're good.
}

sub isPaid {
	return 1;
}

sub checkVersion {
}

sub getLicenseKey {
	local('$handle $data $file');
	$file = getFileProper(systemProperties()["user.home"], ".cobaltstrike.license");
	if (-exists $file && -canread $file) {
		$handle = openf($file);
		$data = readln($handle);
		closef($handle);
		return ["$data" trim];
	}
	else {
		warn("License file is missing. Run Cobalt Strike update program to fix: http://www.advancedpentest.com/help-update-cobalt-strike");
		return "";
	}
}
