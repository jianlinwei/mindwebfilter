//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb/.com).
//For support go to http://groups.yahoo.com/group/dansguardian

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#ifndef __HPP_FATCONTROLLER
#define __HPP_FATCONTROLLER


// INCLUDES

#include "OptionContainer.hpp"
#include "UDSocket.hpp"

#include <string>



// DECLARATIONS

// program main loop - pass in FD of pidfile
int fc_controlit();
// URL cache processes
int url_list_listener(bool logconerror);
// send flush message over URL cache IPC socket
void flush_urlcache();

// fork off into background
bool daemonise();
// create specified amount of child processes
int prefork(int num);

// check child process is ready to start work
bool check_kid_readystatus(int tofind);
// child process informs parent process that it is ready
int send_readystatus(UDSocket &pipe);

// child process main loop - sits waiting for incoming connections & processes them
int handle_connections(UDSocket &pipe);
// tell a non-busy child process to accept the incoming connection
void tellchild_accept(int num, int whichsock);
// child process accept()s connection from server socket
bool getsock_fromparent(UDSocket &fd);

// add known info about a child to our info lists
void addchild(int pos, int fd, pid_t child_pid);
// find ID of first non-busy child
int getfreechild();
// find an empty slot in our child info lists
int getchildslot();
// cull up to this number of non-busy children
void cullchildren(int num);
// delete this child from our info lists
void deletechild(int child_pid);
// clean up any dead child processes (calls deletechild with exit values)
void mopup_afterkids();

// tidy up resources for a brand new child process (uninstall signal handlers, delete copies of unnecessary data, etc.)
void tidyup_forchild();

// send SIGTERM or SIGHUP to call children
void kill_allchildren();
void hup_allchildren();

// setuid() to proxy user (not just seteuid()) - used by child processes & logger/URL cache for security & resource usage reasons
bool drop_priv_completely();

int log_listener();

#endif
