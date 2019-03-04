/*
* Copyright (c) 2015-2016, 2018 Genome Research Ltd.
*
* Author: Andrew Whitwham <aw7+github@sanger.ac.uk>
*
* This file is part of tears.
*
* tears is free software: you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
* details.
*
* You should have received a copy of the GNU General Public License along with
* this program. If not, see <http://www.gnu.org/licenses/>.
*/

/*
*
* tears - streaming a file into iRODS
*
* Andrew Whitwham, November 2015
*
*/

#include "tears_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <rodsClient.h>

#define DEFAULT_BUFFER_SIZE 1048576

void usage_and_exit(char *pname, int exit_code) {
    fprintf(stdout, "Usage: %s [-b bytes -v -d -f] -w /path/to/irods/file < filein \n", pname);
    fprintf(stdout, "    or %s [-b bytes -v -d] [-r] /path/to/irods/file > fileout\n\n", pname);
    fprintf(stdout, "%s, a program to stream data in to or out of iRODS.\n\n", PACKAGE);
    fprintf(stdout, "\t-w\t\twrite to iRODS\n");
    fprintf(stdout, "\t-r\t\tread from iRODS (default)\n");
    fprintf(stdout, "\t-b bytes\tread/write buffer (default %d)\n", DEFAULT_BUFFER_SIZE);
    fprintf(stdout, "\t-v\t\tverbose mode\n");
    fprintf(stdout, "\t-d\t\tuse default server\n");
    fprintf(stdout, "\t-f\t\tforce overwrite of existing file on iRODS\n");
    fprintf(stdout, "\t-h\t\tprint this help\n\n");
    fprintf(stdout, "Version: %s  Author: %s\n", PACKAGE_STRING, PACKAGE_BUGREPORT);
    fprintf(stdout, "Github: %s\n", PACKAGE_URL);
    exit(exit_code);
}


char *get_irods_error_name(int status, int verb) {
    char *subname = 0;
    char *name;
    name = rodsErrorName(status, &subname);

    if (verb) {
        fprintf(stderr, "Extra error message: %s\n", subname);
    }

    return name;
}


void print_irods_error(char *msg, rErrMsg_t *err) {
    char *subname = 0;
    char *name    = rodsErrorName(err->status, &subname);

    fprintf(stderr, "%s name %s (%s) (%d) %s\n", msg, name, subname,
                err->status, err->msg);
}


void error_and_exit(rcComm_t *c, const char *msg, ...) {
    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);

    if (c) {
        rcDisconnect(c);
    }

    exit(EXIT_FAILURE);
}


int irods_uri_check(char *uri, rodsEnv *env, int verb) {
    char *user = NULL;
    char *zone = NULL;
    char *host = NULL;
    char *port = NULL;

    if (strncmp(uri, "irods:", 6) != 0) {
        if (verb) {
            fprintf(stderr, "No iRODS URI, using default settings.\n");
        }

        return 0;
    }

    char *auth  = strstr(uri, "//");
    char *tag_start;
    char *port_end;

    if (auth) {
        tag_start = auth + strlen("//");
        port_end  = strchr(tag_start, '/');
    }

    if (!auth || !port_end) {
        fprintf(stderr, "URI format needed: irods://[irodsUserName%%23irodsZone@][irodsHost][:irodsPort]/collection_path/data_object\n");
        return -1;
    }

    // look for the user name
    char *tag_end = strstr(uri, "%23");

    if (tag_end) {
        user = strndup(tag_start, tag_end - tag_start);
        tag_start = tag_end + strlen("%23");
    }

    // look for zone
    tag_end = strchr(uri, '@');

    if (tag_end) {
        zone = strndup(tag_start, tag_end - tag_start);
        tag_start = tag_end + 1;
    }

    // now the host and port
    tag_end = strchr(auth, ':');
    char *host_tag = tag_end + 1;

    if (tag_end) {
        host = strndup(tag_start, tag_end - tag_start);
        port = strndup(host_tag, port_end - host_tag);
    } else {
        host = strndup(tag_start, port_end - tag_start);
    }

    if (!host) {
        fprintf(stderr, "Error: invalid uri (no host): %s\n", uri);
        return -1;
    }

    // copy of the changed values
    if (user) {
        strncpy(env->rodsUserName, user, NAME_LEN);
    }

    if (zone) {
        strncpy(env->rodsZone, zone, NAME_LEN);
    }

    if (host) {
        strncpy(env->rodsHost, host, NAME_LEN);
    }

    if (port) {
        env->rodsPort = atoi(port);
    }

    // rewrite so just the file is left
    char *file = strdup(port_end);

    if (file) {
        strcpy(uri, file);
    } else {
        fprintf(stderr, "Error: unable to extract file name %s\n", uri);
        return -1;
    }

    if (verb) {
        fprintf(stderr, "File name is %s\n", uri);
    }

    free(file);
    free(user);
    free(zone);
    free(host);
    free(port);

    // success
    return 1;
}


void choose_server(rcComm_t **cn, char *host, rodsEnv *env, int verb) {

    if (verb) {
        fprintf(stderr, "Chosen server is: %s\n", host);
    }

    if (host && strcmp(host, THIS_ADDRESS)) {
        int       stat;
        rErrMsg_t err_msg;
        rcComm_t  *new_cn = NULL;

        new_cn = rcConnect(host, env->rodsPort, env->rodsUserName,
                           env->rodsZone, 0, &err_msg);

        if (!new_cn) {
            fprintf(stderr, "Error: rcReconnect failed with status %d.  Continuing with original server.\n", err_msg.status);
            return;
        }

        #if IRODS_VERSION_INTEGER && IRODS_VERSION_INTEGER >= 4001008
            stat = clientLogin(new_cn, "", "");
        #else
            stat = clientLogin(new_cn);
        #endif

        if (stat < 0) {
            rcDisconnect(new_cn);
            error_and_exit(*cn, "Error: clientLogin failed with status %d:%s\n", stat, get_irods_error_name(stat, verb));
        } else {
            rcDisconnect(*cn);
            *cn = new_cn;
        }
    }
}


int main (int argc, char **argv) {
    rcComm_t           *conn = NULL;
    rodsEnv            irods_env;
    rErrMsg_t          err_msg;
    dataObjInp_t       data_obj;
    openedDataObjInp_t open_obj;
    int                open_fd;
    char    	       *new_host = NULL;

    int status;
    char *obj_name = NULL;
    char *buffer;
    char prog_name[255];
    size_t buf_size = DEFAULT_BUFFER_SIZE;
    int verbose = 0;
    int opt;
    unsigned long total_written = 0;
    int write_to_irods = 0;
    int server_set = 0;
    int force_write = 0;

    while ((opt = getopt(argc, argv, "b:vhrdwf")) != -1) {
    	switch (opt) {
	    case 'b':
	    	buf_size = atoi(optarg);

            if (buf_size <= 0) {
                error_and_exit(conn, "Error: buffer size must be greater than 0.\n");
            }

            break;

	    case 'v':
	    	verbose = 1;
            break;

	    case 'r':
	    	write_to_irods = 0;
            break;

	    case 'w':
	    	write_to_irods = 1;
            break;

	    case 'd':
	    	server_set = 1;
            break;

        case 'f':
            force_write = 1;
            break;

	    case 'h':
	    	usage_and_exit(argv[0], EXIT_SUCCESS);
            break;

	    default:
	    	usage_and_exit(argv[0], EXIT_FAILURE);
            break;
        }
    }

    if (optind >= argc) {
    	fprintf(stderr, "Error: Missing iRODS file.\n");
        usage_and_exit(argv[0], EXIT_FAILURE);
    }

    obj_name = argv[optind];

    if ((buffer = malloc(buf_size)) == NULL) {
    	error_and_exit(conn, "Error: unable to set buffer to size %ld\n", buf_size);
    }

    // set the client name so iRODS knows what program is connecting to it
    sprintf(prog_name, "%s:%s", PACKAGE_NAME, PACKAGE_VERSION);

    if (verbose) {
    	fprintf(stderr, "Setting client name to: %s\n", prog_name);
    }

    setenv(SP_OPTION, prog_name, 1);

    // lets get the irods environment
    if ((status = getRodsEnv(&irods_env)) < 0) {
    	error_and_exit(conn, "Error: getRodsEnv failed with status %d:%s\n", status, get_irods_error_name(status, verbose));
    }

    if ((status = irods_uri_check(obj_name, &irods_env, verbose)) < 0) {
    	error_and_exit(conn, "Error: invalid uri: %s\n", obj_name);
    } else if (status > 0) {
    	server_set = 1;
    }

    if (verbose) {
    	fprintf(stderr, "host %s\nzone %s\nuser %s\nport %d\n",
	    irods_env.rodsHost, irods_env.rodsZone,
	    irods_env.rodsUserName, irods_env.rodsPort);
    }

    #if IRODS_VERSION_INTEGER && IRODS_VERSION_INTEGER >= 4001008
        init_client_api_table();
    #endif

    // make the irods connections
    conn = rcConnect(irods_env.rodsHost, irods_env.rodsPort,
    	    	     irods_env.rodsUserName, irods_env.rodsZone,
                     0, &err_msg);

    if (!conn) {
    	print_irods_error("Error: rcConnect failed:", &err_msg);
        exit(EXIT_FAILURE);
    }

    #if IRODS_VERSION_INTEGER && IRODS_VERSION_INTEGER >= 4001008
        status = clientLogin(conn, "", "");
    #else
        status = clientLogin(conn);
    #endif

    if (status < 0) {
    	error_and_exit(conn, "Error: clientLogin failed with status %d:%s\n", status, get_irods_error_name(status, verbose));
    }

    // set up the data object
    memset(&data_obj, 0, sizeof(data_obj));
    strncpy(data_obj.objPath, obj_name, MAX_NAME_LEN);

    if (write_to_irods) {
    	data_obj.openFlags = O_WRONLY;
    } else {
    	data_obj.openFlags = O_RDONLY;
    }

    data_obj.dataSize = 0;

    // talk to server
    if (write_to_irods) {
        if (!server_set) {
            if ((status = rcGetHostForPut(conn, &data_obj, &new_host)) < 0) {
                error_and_exit(conn, "Error: rcGetHostForPut failed with status %d:%s\n", status, get_irods_error_name(status, verbose));
            }

            choose_server(&conn, new_host, &irods_env, verbose);
            free(new_host);
        }

        if (force_write) {
            addKeyVal(&data_obj.condInput, FORCE_FLAG_KW, "");
        }

        if ((open_fd = rcDataObjCreate(conn, &data_obj)) < 0) {
            error_and_exit(conn, "Error: rcDataObjCreate failed with status %d:%s\n", open_fd, get_irods_error_name(open_fd, verbose));
        }
    } else {
    	if (!server_set) {
            if ((status = rcGetHostForGet(conn, &data_obj, &new_host)) < 0) {
                error_and_exit(conn, "Error: rcGetHostForGet failed with status %d:%s\n", status, get_irods_error_name(status, verbose));
            }

        choose_server(&conn, new_host, &irods_env, verbose);
	    free(new_host);
        }

        if ((open_fd = rcDataObjOpen(conn, &data_obj)) < 0) {
            error_and_exit(conn, "Error: rcDataObjOpen failed with status %d:%s\n", open_fd, get_irods_error_name(open_fd, verbose));
        }
    }

    // the read/write loop
    while (1) {
        bytesBuf_t data_buffer;
        long read_in;
        long written_out;

        // set up common data elements
        memset(&open_obj, 0, sizeof(open_obj));
        open_obj.l1descInx = open_fd;
        data_buffer.buf = buffer;

        // time to read something
        if (write_to_irods) {
            read_in 	    = fread(buffer, 1, buf_size, stdin);
            open_obj.len    = read_in;
            data_buffer.len = open_obj.len;
        } else {
            open_obj.len = buf_size;
            data_buffer.len = open_obj.len;

            if ((read_in = rcDataObjRead(conn, &open_obj, &data_buffer)) < 0) {
                error_and_exit(conn, "Error:  rcDataObjRead failed with status %ld:%s\n", read_in, get_irods_error_name(read_in, verbose));
            }
        }

        if (verbose) {
            fprintf(stderr, "%ld bytes read\n", read_in);
        }

        if (!read_in) break;

        // now try and write something
        if (write_to_irods) {
            open_obj.len = read_in;
            data_buffer.len = open_obj.len;

            if ((written_out = rcDataObjWrite(conn, &open_obj, &data_buffer)) < 0) {
                error_and_exit(conn, "Error:  rcDataObjWrite failed with status %ld\n", written_out, get_irods_error_name(written_out, verbose));
            }
        } else {
            written_out = fwrite(buffer, 1, read_in, stdout);
        }

        if (verbose) {
            fprintf(stderr, "%ld bytes written\n", written_out);
        }

        total_written += written_out;

        if (read_in != written_out) {
            error_and_exit(conn, "Error: write fail %ld written, should be %ld.\n", written_out, read_in);
        }
    };

    if (verbose) {
    	fprintf(stderr, "Total bytes written %ld\n", total_written);
    }

    if ((status = rcDataObjClose(conn, &open_obj)) < 0) {
    	error_and_exit(conn, "Error: rcDataObjClose failed with status %d:%s\n", status, get_irods_error_name(status, verbose));
    }

    rcDisconnect(conn);
    free(buffer);
    exit(EXIT_SUCCESS);
}
