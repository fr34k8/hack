#
# A serialized object data store built on top of Metasploit's notes table
#

# grab raw rows...
sub data_raw {
	return _data_raw($mclient, $1);
}

sub _data_raw {
	return call($1, "db.key_values", $2)["values"];
}

sub data_list {
	return _data_list($mclient, $1);
}

# %hash = _data_list($client, 'key')
sub _data_list {
	local('$raw $buffer $object $item %r $id');
	%r = ohash();
	foreach $item (_data_raw($1, $2)) {
		$id = $item['id'];

		# deserialize object...
		$raw = $item['data'];
		$buffer = allocate(1024);
		writeb($buffer, [msf.Base64 decode: $raw]);
		closef($buffer);
		$object = readObject($buffer);
		closef($buffer);

		%r[$id] = $object;
	}
	return %r;
}

# data_clear('key') -- clears all data associated with the specified key
sub data_clear {
	call($mclient, "db.key_clear", $1);
}

# data_delete('id') -- delete the specified row
sub data_delete {
	call($mclient, "db.key_delete", $1);
}

sub data_serialize {
	local('$buffer $data');
	# serialize the data...
	$buffer = allocate(1024);
	writeObject($buffer, $1);
	closef($buffer);
	$data = [msf.Base64 encode: cast(readb($buffer, -1), 'b')];
	closef($data);
	return $data;
}

# data_add('key', $object) -- appends value into the database... 
sub data_add {
	call($mclient, "db.key_add", $1, data_serialize($2));
}

sub data_add_async {
	call_async($mclient, "db.key_add", $1, data_serialize($2));
}
