# tears
Stream files to and from iRODS.

tears either reads from stdin and writes a file to iRODS or reads a file from iRODS and writes to stdout.  Basic usage for writing is:

file_making_program | tears -w /path/to/irods/file

or for reading:

tears /path/to/irods/file | file_receiving_program

Two things to note.  Firstly, tears will try to pick the best iRODS host to read or write from.  This can cause authentication problems and can be switched off by using the -d option.  Secondly, the iRODS file can be in the form of a URI (proposed [here](https://github.com/samtools/htslib/issues/229)).  The URI is of the form:

irods://[irodsUserName%23irodsZone@][irodsHost][:irodsPort]/collection_path/data_object





