/* scan_eaton_serial.c: detect Eaton serial XCP, SHUT and Q1 devices
 * 
 *  Copyright (C) 2012  Arnaud Quette <ArnaudQuette@eaton.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* prevent inclusion of common.h and main.h */
#define NUT_COMMON_H
#define MAIN_H

/* From common.h */
#include "config.h"		/* must be the first header */

/* Need this on AIX when using xlc to get alloca */
#ifdef _AIX
#pragma alloca
#endif /* _AIX */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <assert.h>

#include "timehead.h"
#include "attribute.h"

#include "nut-scan.h"
/* FIXME: to be put in nut-scan.h? */
extern int printq(int quiet,const char *fmt, ...);
int quiet = 0;

#include "serial.h"
/* XCP headers: we don't include bcmxcp_io.h since it pulls main.h... */
int command_read_sequence(unsigned char command, unsigned char *data);
void pw_comm_setup(const char *port);

/* FIXME: related to a common baudrate hunting function in serial.c */
struct mypw_baud_rate {
	int rate;
	int name;
} mypw_baud_rates[] = {
	{ B19200, 19200 },
	{ B9600,  9600 },
	{ B4800,  4800 },
	{ B2400,  2400 },
	{ B1200,  1200 },
	/* end of structure. */
	{ 0,  0 }
};

/* Remap some functions to avoid undesired behavior (drivers/main.c) */
char *getval(const char *var) {	return NULL; }

/* Remap some functions to avoid undesired behavior (common.c) */
void upsdebug_hex(int level, const char *msg, const void *buf, int len) { ; }
void upsdebugx(int level, const char *fmt, ...) { ; }
void fatalx(int status, const char *fmt, ...) { ; }
void fatal_with_errno(int status, const char *fmt, ...) { ; }
void upslogx(int priority, const char *fmt, ...) { ; }

/* FIXME: extracted from common.c */
/* Read up to buflen bytes from fd and return the number of bytes
   read. If no data is available within d_sec + d_usec, return 0.
   On error, a value < 0 is returned (errno indicates error). */
int select_read(const int fd, void *buf, const size_t buflen, const long d_sec, const long d_usec)
{
	int		ret;
	fd_set		fds;
	struct timeval	tv;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	tv.tv_sec = d_sec;
	tv.tv_usec = d_usec;

	ret = select(fd + 1, &fds, NULL, NULL, &tv);

	if (ret < 1) {
		return ret;
	}

	return read(fd, buf, buflen);
}

/* non fatal version of serial.c->ser_set_speed() */
int myser_set_speed(int fd, const char *port, speed_t speed);

#include "bcmxcp.h"

/* SHUT header */
#define SHUT_SYNC 0x16
#define MAX_TRY   4

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* Local list of found devices */
static nutscan_device_t * dev_ret = NULL;

#ifdef HAVE_PTHREAD
static pthread_mutex_t dev_mutex;
#endif

/* Drivers name */
#define SHUT_DRIVER_NAME  "mge-shut"
#define XCP_DRIVER_NAME   "bcmxcp"
#define Q1_DRIVER_NAME    "blazer_ser"

/* Fake driver main, for using serial functions, needed for bcmxcp_ser.c */
char  *device_path;
int   upsfd;
int   exit_flag = 0;
int   do_lock_port;

/* By default, scan 10 ports (auto) */
#define DEFAULT_PORT_MAX	10

/* Limit to 10 ports per pattern */
#define NB_PORT_MAX_PER_PORTPATTERN	10

/* Global limit to 100 (!) ports */
#define NB_PORT_MAX	100

 * FIXME: modularization to reuse code! */
/* we could here have used send_command() directly, but it's static */
extern void send_write_command(unsigned char *command, int command_length);

/* Functions extracted from drivers/bcmxcp.c, to avoid pulling too many things
/* lightweight function to calculate the 8-bit
 * two's complement checksum of buf, using XCP data length (including header)
 * the result must be 0 for the sequence data to be valid */
int checksum_test(const unsigned char *buf)
{
	unsigned char checksum = 0;
	int i, length;

	/* buf[2] is the length of the XCP frame ; add 5 for the header */
	length = (int)(buf[2]) + 5;

	for (i = 0; i < length; i++) {
		checksum += buf[i];
	}
	/* Compute the 8-bit, Two's Complement checksum now and return it */
	checksum = ((0x100 - checksum) & 0xFF);
	return (checksum == 0);
}

unsigned char calc_checksum(const unsigned char *buf)
{
	unsigned char c;
	int i;

	c = 0;
	for(i = 0; i < 2 + buf[1]; i++)
		c -= buf[i];

	return c;
}

typedef struct {
	char *name_pattern;
	/* "=" or "+?" (where "?" is a number, equivalent to the Ascii offset) */
	char *increment_rule;
} portname_pattern_t;

#define BASE_INDEX 48 /* (zero '0') in Ascii table */

/* generalise to %c for Solaris, and use Ascii table
 * Base10 '48' is the base (zero '0')
 * Base10 '97' (+49) to get alpha notation for Solaris */
portname_pattern_t portname_patterns[] = {
	/* FIXME: needs Vasek nut_platform.h defines */
/* #if (defined NUT_PLATFORM_LINUX) */
	{ "/dev/ttyS%c", "=" },
	{ "/dev/ttyUSB%c", "=" },
	/* HP UX */
/*	{ "/dev/tty%ip0", "=" }, */
/*	{ "/dev/tty0%i", "=" }, */ /* osf/1 and Digital UNIX style */
	/* IBM AIX */
/*	{ "/dev/tty%i", "=" }, */
	/* Solaris */
/*	{ "/dev/tty%c", "+49" }, */ /* not numeric (0, 1, ...) but alpha (a, b) */
	/* SGI IRIX */
/*	{ "/dev/ttyd%i", "=" }, */
/*	{ "/dev/ttyf%i", "=" }, */
	/* Windows */
/*	{ "COM%i", "+" }, */
/* FIXME: Mac OS X has no serial port, but maybe ttyUSB? */
	/* end of structure. */
	{ NULL, 0 }
};

/* #if (defined NUT_PLATFORM_MS_WINDOWS) */
/* Windows: all serial port names start with "COM"
#define SERIAL_PORT_PREFIX "COM" */

/* Unix: all serial port names start with "/dev/tty" */
#define SERIAL_PORT_PREFIX "/dev/tty"

/* Return 1 if port_name is a full path name to a serial port,
 * as per SERIAL_PORT_PREFIX */
static int is_serial_port_path(const char * port_name)
{
	printq(quiet, "\nSERIAL_PORT_PREFIX len = %i\n", strlen(SERIAL_PORT_PREFIX));
	if (!strncmp(port_name, SERIAL_PORT_PREFIX, strlen(SERIAL_PORT_PREFIX))) {
		return 1;
	}
	return 0;
}

/* Return a list of serial ports name, in 'ports_list', according to the OS,
 * the provided 'ports_range', and the number of available ports */
static int get_serial_ports_list(const char *ports_range, char **ports_list)
{
	int  start_port = 0, stop_port = 0;
	int  current_port = 0;
	char * list_sep_ptr = NULL;
	portname_pattern_t *cur_port_pattern = NULL;
	int increment_offset = 0; /* equivalent to '=' */
	int nb_ports = 0;
	memset(ports_list, 0, 30);

	/* 1) check ports_list */
	if ((ports_range == NULL) || (!strncmp(ports_range, "auto", 4))) {
		stop_port = DEFAULT_PORT_MAX;
	}
	else {
		/* we have a list:
		 * - single element: X (digit) or port name (COM1, /dev/ttyS0, ...)
		 * - range list: X-Y
		 * - multiple elements (coma separated): /dev/ttyS0,/dev/ttyUSB0 */
		if ( (list_sep_ptr = strchr(ports_range, '-')) != NULL ) {
			start_port = atoi(ports_range);
			stop_port = atoi(++list_sep_ptr);
		}
		else if ( ((list_sep_ptr = strchr(ports_range, ',')) != NULL )
				&& (is_serial_port_path(ports_range)) ) {
			/* FIXME: else, coma sep. list: /dev/ttyS2-/dev/ttyS4
			 * 	split using strtok()..., append to ports_list, count nb_ports and return
			 * 		beware of the NB_PORT_MAX
			 * } */
			;
		}
		else {
			/* we have been provided a single port name */
			start_port = stop_port = atoi(ports_range);
		}
	}

	/* Sanity checks */
	nb_ports = stop_port - start_port;
	if (nb_ports >= NB_PORT_MAX_PER_PORTPATTERN) {
		printq(quiet, "Limiting range for Eaton serial scan to %i ports\n", NB_PORT_MAX_PER_PORTPATTERN);
		stop_port = (start_port + NB_PORT_MAX_PER_PORTPATTERN) -1;
	}
	/* Reset the ports number count */
	nb_ports = 0;

	printq(quiet, "start_port = %i, stop_port = %i\n", start_port, stop_port);

	/* for each pattern, generate a port list */
	for (cur_port_pattern = portname_patterns ;
			cur_port_pattern->name_pattern != NULL ; cur_port_pattern++) {
		
		switch (cur_port_pattern->increment_rule[0])
		{
			case '+':
				increment_offset = atoi(&cur_port_pattern->increment_rule[1]);
				break;
			default:
			case '=':
				increment_offset = 0;
				break;
		}

		/* For each value in the range, generate a port entry
		 * BEWARE: going beyond NB_PORT_MAX_PER_PORTPATTERN (i.e 10) will
		 * result in weird port numbers! */
		for (current_port = start_port ; current_port <= stop_port ; current_port++) {

			ports_list[nb_ports] = (char *)malloc(32);
			/* Note: this also addresses Solaris, and alpha notation! */
			snprintf(ports_list[nb_ports], 31, cur_port_pattern->name_pattern,
				(BASE_INDEX + increment_offset + current_port));
			nb_ports++;
		}
	}
	return nb_ports;
}

/*******************************************************************************
 * SHUT functions (MGE legacy, but Eaton path forward)
 ******************************************************************************/

/* Light version of of drivers/libshut.c->shut_synchronise()
 * return 1 if OK, 0 otherwise */
int shut_synchronise(int upsfd)
{
	int try;
	u_char reply = '\0';

	/* Sync with the UPS according to notification */
	for (try = 0; try < MAX_TRY; try++) {
		if ((ser_send_char(upsfd, SHUT_SYNC)) == -1) {
			continue;
		}

		ser_get_char(upsfd, &reply, 1, 0);
		if (reply == SHUT_SYNC) {
			return 1;
		}
	}
	return 0;
}

/* SHUT scan:
 *   send SYNC token (0x16) and receive the SYNC token back
 *   FIXME: maybe try to get device descriptor?!
 */
nutscan_device_t * nutscan_scan_eaton_serial_shut(const char* port_name)
{
	nutscan_device_t * dev = NULL;
	int devfd = -1;

	/* BEWARE: don't use ser_open() since it calls fatalx()! */
	if ( (devfd = open(port_name, O_RDWR | O_NOCTTY | O_EXCL | O_NONBLOCK)) != -1) {
		
		/* set RTS to on and DTR to off first, as these are not fatal
		 * and allow to test the port */
		if (ser_set_dtr(devfd, 0) != -1) {

			ser_set_rts(devfd, 1);
			/* now we can safely call ser_set_speed(), which is fatal */
			myser_set_speed(devfd, port_name, B2400);

			if (shut_synchronise(devfd)) {

				/* Communication established successfully! */
				dev = nutscan_new_device();
				dev->type = TYPE_EATON_SERIAL;
				dev->driver = strdup(SHUT_DRIVER_NAME);
				dev->port = strdup(port_name);
#ifdef HAVE_PTHREAD
				pthread_mutex_lock(&dev_mutex);
#endif
				dev_ret = nutscan_add_device_to_device(dev_ret, dev);
#ifdef HAVE_PTHREAD
				pthread_mutex_unlock(&dev_mutex);
#endif
			}
		}
		/* Close the device */
		ser_close(devfd, NULL);
	}

	return dev;
}

/*******************************************************************************
 * XCP functions (Eaton Powerware legacy)
 ******************************************************************************/

/* XCP scan:
 *   baudrate nego (...)
 *   Send ESC to take it out of menu
 *   Wait 90ms
 *   Send auth command (AUTHOR[4] = {0xCF, 0x69, 0xE8, 0xD5};)
 *   Wait 500ms (or less?)
 *   Send PW_SET_REQ_ONLY_MODE command (0xA0) and wait for response
 *   [Get ID Block (PW_ID_BLOCK_REQ) (0x31)]
 */
nutscan_device_t * nutscan_scan_eaton_serial_xcp(const char* port_name)
{
	nutscan_device_t * dev = NULL;
	int i, ret, devfd = -1;
	unsigned char	answer[256];
	unsigned char	AUT[4] = { 0xCF, 0x69, 0xE8, 0xD5 }; /* Autorisation command */
	unsigned char	sbuf[128];

	memset(sbuf, 0, 128);

	/* BEWARE: don't use ser_open() since it calls fatalx()! */
	if ( (devfd = open(port_name, O_RDWR | O_NOCTTY | O_EXCL | O_NONBLOCK)) != -1) {

#ifdef HAVE_PTHREAD
		pthread_mutex_lock(&dev_mutex);
#endif
		upsfd = devfd;
#ifdef HAVE_PTHREAD
		pthread_mutex_unlock(&dev_mutex);
#endif

		for (i=0; (mypw_baud_rates[i].rate != 0) && (dev == NULL); i++)
		{
			memset(answer, 0, 256);

			if (myser_set_speed(devfd, port_name, mypw_baud_rates[i].rate) == -1)
				break;

			ret = ser_send_char(devfd, 0x1d);	/* send ESC to take it out of menu */
			if (ret <= 0)
				break;

			usleep(90000);
			send_write_command(AUT, 4);
			usleep(500000);
			
			/* Discovery with Baud Hunting (XCP protocol spec. §4.1.2)
			 * sending PW_SET_REQ_ONLY_MODE should be enough, since
			 * the unit should send back Identification block */
			sbuf[0] = PW_COMMAND_START_BYTE;
			sbuf[1] = (unsigned char)1;
			sbuf[2] = PW_SET_REQ_ONLY_MODE;
			sbuf[3] = calc_checksum(sbuf);
			ret = ser_send_buf_pace(devfd, 1000, sbuf, 4);

			/* Read PW_COMMAND_START_BYTE byte */
			ret = ser_get_char(devfd, answer, 1, 0);

#if 0
			/* FIXME: seems not needed, but requires testing with more devices! */
			if (ret <= 0) {
				usleep(250000); /* 500000? */
				memset(answer, 0, 256);
				ret = command_sequence(&id_command, 1, answer);
			}
#endif

			if ( (ret > 0) && (answer[0] == PW_COMMAND_START_BYTE) ) {
				dev = nutscan_new_device();
				dev->type = TYPE_EATON_SERIAL;
				dev->driver = strdup(XCP_DRIVER_NAME);
				dev->port = strdup(port_name);
#ifdef HAVE_PTHREAD
				pthread_mutex_lock(&dev_mutex);
#endif
				dev_ret = nutscan_add_device_to_device(dev_ret, dev);
#ifdef HAVE_PTHREAD
				pthread_mutex_unlock(&dev_mutex);
#endif
				break;
			}
			usleep(100000);
		}
		/* Close the device */
		ser_close(devfd, NULL);
	}

	return dev;
}

/*******************************************************************************
 * Q1 functions (Phoenixtec/Centralion/Santak, still Eaton path forward)
 ******************************************************************************/

#define SER_WAIT_SEC  1  /* 3 seconds for Best UPS */
#define MAXTRIES      3

/* Q1 scan:
 *   - open the serial port and set the speed to 2400 baud
 *   - simply try to get Q1 (status) string
 *   - check its size and first char. which should be '('
 */
nutscan_device_t * nutscan_scan_eaton_serial_q1(const char* port_name)
{
	nutscan_device_t * dev = NULL;
	struct termios tio;
	int ret = 0, retry;
	int devfd = -1;
	char buf[128];

	/* BEWARE: don't use ser_open() since it calls fatalx()! */
	if ( (devfd = open(port_name, O_RDWR | O_NOCTTY | O_EXCL | O_NONBLOCK)) != -1) {

		if (myser_set_speed(devfd, port_name, B2400) != -1) {

			if (!tcgetattr(devfd, &tio)) {

				/* Use canonical mode input processing (to read reply line) */
				tio.c_lflag |= ICANON;	/* Canonical input (erase and kill processing) */

				tio.c_cc[VEOF]   = _POSIX_VDISABLE;
				tio.c_cc[VEOL]   = '\r';
				tio.c_cc[VERASE] = _POSIX_VDISABLE;
				tio.c_cc[VINTR]  = _POSIX_VDISABLE;
				tio.c_cc[VKILL]  = _POSIX_VDISABLE;
				tio.c_cc[VQUIT]  = _POSIX_VDISABLE;
				tio.c_cc[VSUSP]  = _POSIX_VDISABLE;
				tio.c_cc[VSTART] = _POSIX_VDISABLE;
				tio.c_cc[VSTOP]  = _POSIX_VDISABLE;

				if (!tcsetattr(devfd, TCSANOW, &tio)) {

					/* Set the default (normal) cablepower */
					ser_set_dtr(devfd, 1);
					ser_set_rts(devfd, 0);

					/* Allow some time to settle for the cablepower */
					usleep(100000);

					/* Only try pure 'Q1', not older ones like 'D' or 'QS'
					 * > [Q1\r]
					 * < [(226.0 195.0 226.0 014 49.0 27.5 30.0 00001000\r]
					 */
					for (retry = 1; retry <= MAXTRIES; retry++) {

						/* simplified code */
						ser_flush_io(devfd);
						if ( (ret = ser_send(devfd, "Q1\r")) > 0) {

							/* Get Q1 reply */
							if ( (ret = ser_get_buf(devfd, buf, sizeof(buf), SER_WAIT_SEC, 0)) > 0) {

								/* Check answer */
								/* should at least (and most) be 46 chars */
								if (ret >= 46) {
									if (buf[0] == '(') {

										dev = nutscan_new_device();
										dev->type = TYPE_EATON_SERIAL;
										dev->driver = strdup(Q1_DRIVER_NAME);
										dev->port = strdup(port_name);
#ifdef HAVE_PTHREAD
										pthread_mutex_lock(&dev_mutex);
#endif
										dev_ret = nutscan_add_device_to_device(dev_ret, dev);
#ifdef HAVE_PTHREAD
										pthread_mutex_unlock(&dev_mutex);
#endif
										break;
									}
								}
							}
						}
					}
				}
			}
		}
		/* Close the device */
		ser_close(devfd, NULL);
	}
	return dev;
}

static void * nutscan_scan_eaton_serial_device(void * port_arg)
{
	nutscan_device_t * dev = NULL;
	char* port_name = (char*) port_arg;

	/* Try SHUT first */
	if ( (dev = nutscan_scan_eaton_serial_shut(port_name)) == NULL) {
		usleep(100000);
		/* Else, try XCP */
		if ( (dev = nutscan_scan_eaton_serial_xcp(port_name)) == NULL) {
			/* Else, try Q1 */
			usleep(100000);
			dev = nutscan_scan_eaton_serial_q1(port_name);
		}
		/* Else try UTalk? */
	}
	return dev;
}

nutscan_device_t * nutscan_scan_eaton_serial(const char* ports_range)
{
	struct sigaction oldact;
	int change_action_handler = 0;
	char *current_port_name = NULL;
	char *serial_ports_list[NB_PORT_MAX];
	int nb_ports = 0;
	int  current_port_nb;
#ifdef HAVE_PTHREAD
	int i;
	pthread_t thread;
	pthread_t * thread_array = NULL;
	int thread_count = 0;

	pthread_mutex_init(&dev_mutex,NULL);
#endif

	/* 1) Get ports_list */
	nb_ports = get_serial_ports_list(ports_range, &serial_ports_list[0]);

	/* Ignore SIGPIPE if the caller hasn't set a handler for it yet */
	if( sigaction(SIGPIPE, NULL, &oldact) == 0 ) {
		if( oldact.sa_handler == SIG_DFL ) {
			change_action_handler = 1;
			signal(SIGPIPE,SIG_IGN);
		}
	}

	/* port(s) iterator */
	for (current_port_nb = 0 ; current_port_nb < nb_ports ; current_port_nb++) {

		current_port_name = serial_ports_list[current_port_nb];
		printq(quiet, "\nprocessing ports = %i (%s)\n", current_port_nb, current_port_name); /* FIXME: to be removed */
#ifdef HAVE_PTHREAD
		if (pthread_create(&thread, NULL, nutscan_scan_eaton_serial_device, (void*)current_port_name) == 0){
			thread_count++;
			thread_array = realloc(thread_array,
					thread_count*sizeof(pthread_t));
			thread_array[thread_count-1] = thread;
		}
#else
		nutscan_scan_eaton_serial_device(current_port_name);
#endif
		fflush(stdout);
	}

#ifdef HAVE_PTHREAD
	for ( i = 0; i < thread_count ; i++) {
		pthread_join(thread_array[i],NULL);
	}
	pthread_mutex_destroy(&dev_mutex);
	free(thread_array);
#endif

	if(change_action_handler) {
		signal(SIGPIPE,SIG_DFL);
	}

	/* free everything... */
	for (current_port_nb = 0 ; current_port_nb < nb_ports ; current_port_nb++) {
	 	free(serial_ports_list[current_port_nb]);
	}
	return dev_ret;
}

/***********************************
* Extracted functions
***********************************/

/* non fatal version of serial.c->ser_set_speed() */
int myser_set_speed(int fd, const char *port, speed_t speed)
{
	struct	termios	tio;

	if (tcgetattr(fd, &tio) != 0) {
		//fatal_with_errno(EXIT_FAILURE, "tcgetattr(%s)", port);
		return -1;
	}

	tio.c_cflag = CS8 | CLOCAL | CREAD;
	tio.c_iflag = IGNPAR;
	tio.c_oflag = 0;
	tio.c_lflag = 0;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

#ifdef HAVE_CFSETISPEED
	cfsetispeed(&tio, speed);
	cfsetospeed(&tio, speed);
#else
#error This system lacks cfsetispeed() and has no other means to set the speed
#endif

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &tio);

	return 0;
}
