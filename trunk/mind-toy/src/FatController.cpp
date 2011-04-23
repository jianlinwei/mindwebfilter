//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@jadeb//.com).
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


// INCLUDES

#ifdef HAVE_CONFIG_H
#include "../mind_config.h"
#endif

#include <cstdlib>
#include <syslog.h>
#include <csignal>
#include <ctime>
#include <sys/stat.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <sys/poll.h>
#include <istream>
#include <map>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>

#ifdef ENABLE_SEGV_BACKTRACE
#include <execinfo.h>
#endif

#include "FatController.hpp"
#include "ConnectionHandler.hpp"
#include "DynamicURLList.hpp"
#include "DynamicIPList.hpp"
#include "String.hpp"
#include "SocketArray.hpp"
#include "UDSocket.hpp"
#include "SysV.hpp"
#include "Logger.hpp"
#include "mind.hpp"


// GLOBALS

// these are used in signal handlers - "volatile" indicates they can change at
// any time, and therefore value reading on them does not get optimised. since
// the values can get altered by outside influences, this is useful.
static volatile bool ttg = false;
static volatile bool gentlereload = false;
static volatile bool sig_term_killall = false;
volatile bool reloadconfig = false;

extern OptionContainer o;
extern bool is_daemonised;
extern Logger log;
extern char* procName;

int numchildren; // to keep count of our children
int busychildren; // to keep count of our children
int waitingfor; // num procs waiting for to be preforked
int *childrenpids; // so when one exits we know who
int *childrenstates; // so we know what they're up to
struct pollfd *pids;
UDSocket **childsockets;
int failurecount;
int serversocketcount;
SocketArray serversockets; // the sockets we will listen on for connections
UDSocket loggersock; // the unix domain socket to be used for ipc with the forked children
UDSocket urllistsock;
UDSocket iplistsock;
Socket *peersock(NULL); // the socket which will contain the connection
String peersockip; // which will contain the connection ip


// DECLARATIONS

// Signal handlers
extern "C" {
    void sig_chld(int signo);
    void sig_term(int signo); // This is so we can kill our children
    void sig_termsafe(int signo); // This is so we can kill our children safer
    void sig_hup(int signo); // This is so we know if we should re-read our config.
    void sig_usr1(int signo); // This is so we know if we should re-read our config but not kill current connections
    void sig_childterm(int signo);
#ifdef ENABLE_SEGV_BACKTRACE
    void sig_segv(int signo/*, siginfo_t* info, void* p*/); // Generate a backtrace on segfault
#endif
}

// signal handlers
extern "C" {

    void sig_term(int signo) {
        sig_term_killall = true;
        ttg = true; // its time to go
    }

    void sig_termsafe(int signo) {
        ttg = true; // its time to go
    }

    void sig_hup(int signo) {
        reloadconfig = true;
#ifdef MIND_DEBUG
        std::cout << "HUP received." << std::endl;
#endif
    }

    void sig_usr1(int signo) {
        gentlereload = true;
#ifdef MIND_DEBUG
        std::cout << "USR1 received." << std::endl;
#endif
    }

    void sig_childterm(int signo) {
#ifdef MIND_DEBUG
        std::cout << "TERM recieved." << std::endl;
#endif
        _exit(0);
    }
#ifdef ENABLE_SEGV_BACKTRACE

    void sig_segv(int signo) {
#ifdef MIND_DEBUG
        std::cout << "SEGV received." << std::endl;
#endif
        // Generate backtrace
        void *addresses[10];
        char **strings;
        int c = backtrace(addresses, 10);
        strings = backtrace_symbols(addresses, c);
        printf("backtrace returned: %d\n", c);
        for (int i = 0; i < c; i++) {
            log.writeToLog(1, "%d: %zX ", i, (size_t) addresses[i]);
            log.writeToLog(1, "%s", strings[i]);
        }
        // Kill off the current process
        raise(SIGTERM);
    }
#endif
}

// completely drop our privs - i.e. setuid, not just seteuid

bool drop_priv_completely() {
    // This is done to solve the problem where the total processes for the
    // uid rather than euid is taken for RLIMIT_NPROC and so can't fork()
    // as many as expected.
    // It is also more secure.
    //
    // Suggested fix by Lawrence Manning Tue 25th February 2003
    //

    int rc = seteuid(o.root_user); // need to be root again to drop properly
    if (rc == -1) {
        log.writeToLog(1, "%s", "Unable to seteuid(suid)");
#ifdef MIND_DEBUG
        std::cout << strerror(errno) << std::endl;
#endif
        return false; // setuid failed for some reason so exit with error
    }
    rc = setuid(o.proxy_user);
    if (rc == -1) {
        log.writeToLog(1, "%s", "Unable to setuid()");
        return false; // setuid failed for some reason so exit with error
    }
    return true;
}

// signal the URL cache to flush via IPC

void flush_urlcache() {
    if (o.url_cache_number < 1) {
        return; // no cache running to flush
    }
    UDSocket fipcsock;
    if (fipcsock.getFD() < 0) {
        log.writeToLog(1, "%s", "Error creating ipc socket to url cache for flush");
        return;
    }
    if (fipcsock.connect((char *) o.urlipc_filename.c_str()) < 0) { // conn to dedicated url cach proc
        log.writeToLog(1, "%s", "Error connecting via ipc to url cache for flush");
#ifdef MIND_DEBUG
        std::cout << "Error connecting via ipc to url cache for flush" << std::endl;
#endif
        return;
    }
    String request("f\n");
    try {
        fipcsock.writeString(request.toCharArray()); // throws on err
    } catch (std::exception & e) {
#ifdef MIND_DEBUG
        std::cerr << "Exception flushing url cache" << std::endl;
        std::cerr << e.what() << std::endl;
#endif
        log.writeToLog(1, "%s", "Exception flushing url cache");
        log.writeToLog(1, "%s", e.what());
    }
}

// Fork ourselves off into the background

bool daemonise() {

#ifdef MIND_DEBUG
    return true; // if debug mode is enabled we don't want to detach
#endif

    if (o.no_daemon || is_daemonised) {
        return true;
    }

    int nullfd = -1;
    if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1) {
        log.writeToLog(1, "%s", "Couldn't open /dev/null");
        return false;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        return false;
    } else if (pid != 0) {
        if (nullfd != -1) {
            close(nullfd);
        }
        exit(0); // parent goes bye-bye
    }
    // child continues
    dup2(nullfd, 0); // stdin
    dup2(nullfd, 1); // stdout
    dup2(nullfd, 2); // stderr
    close(nullfd);

    setsid(); // become session leader
    chdir("/"); // change working directory
    umask(0); // clear our file mode creation mask

    is_daemonised = true;

    return true;
}


// *
// *
// *  child process code
// *
// *

// prefork specified num of children and set them handling connections

int prefork(int num) {
    if (num < waitingfor) {
        return 3; // waiting for forks already
    }
#ifdef MIND_DEBUG
    std::cout << "attempting to prefork:" << num << std::endl;
#endif
    int sv[2];
    pid_t child_pid;
    while (num--) {
        if (numchildren >= o.max_children) {
            return 2; // too many - geddit?
        }
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            return -1; // error
        }

        child_pid = fork();

        if (child_pid == -1) { // fork failed, for example, if the
            // process is not allowed to create
            // any more
            log.writeToLog(1, "%s", "Unable to fork() any more.");
#ifdef MIND_DEBUG
            std::cout << "Unable to fork() any more." << std::endl;
            std::cout << strerror(errno) << std::endl;
            std::cout << "numchildren:" << numchildren << std::endl;
#endif
            failurecount++; // log the error/failure
            // A DoS attack on a server allocated
            // too many children in the conf will
            // kill the server.  But this is user
            // error.
            sleep(1); // need to wait until we have a spare slot
            num--;
            continue; // Nothing doing, go back to listening
        } else if (child_pid == 0) {
            // I am the child - I am alive!
            close(sv[0]); // we only need our copy of this
            tidyup_forchild();
            if (!drop_priv_completely()) {
                return -1; //error
            }
            // no need to deallocate memory etc as already done when fork()ed

            // right - let's do our job!
            UDSocket sock(sv[1]);
            int rc = handle_connections(sock);

            // ok - job done, time to tidy up.
            _exit(rc); // baby go bye bye
        } else {
            // I am the parent
            // close the end of the socketpair we don't need
            close(sv[1]);
            // add the child and its FD/PID to an empty child slot
            addchild(getchildslot(), sv[0], child_pid);
#ifdef MIND_DEBUG
            std::cout << "Preforked parent added child to list" << std::endl;
#endif
        }
    }
    return 1; // parent returning
}

// cleaning up for brand new child processes - only the parent needs the signal handlers installed, and so forth

void tidyup_forchild() {
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = &sig_childterm;
    if (sigaction(SIGTERM, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGTERM" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGTERM");
    }
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGUSR1" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGUSR1");
    }
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = &sig_hup;
    if (sigaction(SIGHUP, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGHUP" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGHUP");
    }
    // now close open socket pairs don't need

    for (int i = 0; i < o.max_children; i++) {
        if (pids[i].fd != -1) {
            delete childsockets[i];
        }
    }
    delete[]childrenpids;
    delete[]childrenstates;
    delete[]childsockets;
    delete[]pids; // 4 deletes good, memory leaks bad
}

// send Ready signal to parent process over the socketpair (used in handle_connections)

int send_readystatus(UDSocket &pipe) { // blocks until timeout
    String message("2\n");
    try {
        if (!pipe.writeToSocket(message.toCharArray(), message.length(), 0, 15, true, true)) {
            return -1;
        }
    } catch (std::exception & e) {
        return -1;
    }
    return 0;
}

// handle any connections received by this child (also tell parent we're ready each time we become idle)

int handle_connections(UDSocket &pipe) {
    ConnectionHandler h; // the class that handles the connections
    String ip;
    bool toldparentready = false;
    int cycle = o.maxage_children;
    int stat = 0;
    reloadconfig = false;

    // stay alive both for the maximum allowed age of child processes, and whilst we aren't supposed to be re-reading configuration
    while (cycle-- && !reloadconfig) {
        if (!toldparentready) {
            if (send_readystatus(pipe) == -1) { // non-blocking (timed)
#ifdef MIND_DEBUG
                std::cout << "parent timed out telling it we're ready" << std::endl;
#endif
                break; // parent timed out telling it we're ready
                // so either parent gone or problem so lets exit this joint
            }
            toldparentready = true;
        }

        if (!getsock_fromparent(pipe)) { // blocks waiting for a few mins
            continue;
        }
        toldparentready = false;

        // now check the connection is actually good
        if (peersock->getFD() < 0 || peersockip.length() < 7) {
            if (o.logconerror)
                log.writeToLog(1, "Error accepting. (Ignorable)");
            continue;
        }

        h.handleConnection(*peersock, peersockip); // deal with the connection
        delete peersock;
    }
    if (!(++cycle) && o.logchildprocs)
        log.writeToLog(1, "Child has handled %d requests and is exiting", o.maxage_children);
#ifdef MIND_DEBUG
    if (reloadconfig) {
        std::cout << "child been told to exit by hup" << std::endl;
    }
#endif
    if (!toldparentready) {
        stat = 2;
    }
    return stat;
}

// the parent process recieves connections - children receive notifications of this over their socketpair, and accept() them for handling

bool getsock_fromparent(UDSocket &fd) {
    String message;
    char buf;
    int rc;
    try {
        rc = fd.readFromSocket(&buf, 1, 0, 360, true, true); // blocks for a few mins
    } catch (std::exception & e) {
        // whoop! we received a SIGHUP. we should reload our configuration - and no, we didn't get an FD.

        reloadconfig = true;
        return false;
    }
    // that way if child does nothing for a long time it will eventually
    // exit reducing the forkpool depending on o.maxage_children which is
    // usually 500 so max time a child hangs around is lonngggg
    // it needs to be a long block to stop the machine needing to page in
    // the process

    // check the message from the parent
    if (rc < 1) {
        return false;
    }

    // woo! we have a connection. accept it.
    peersock = serversockets[buf]->accept();
    peersockip = peersock->getPeerIP();

    try {
        fd.writeToSockete("K", 1, 0, 10, true); // need to make parent wait for OK
        // so effectively providing a lock
    } catch (std::exception & e) {
        if (o.logconerror)
            log.writeToLog(1, "Error telling parent we accepted: %s", e.what());
        peersock->close();
        return false;
    }

    return true;
}


// *
// *
// * end of child process code
// *
// *


// *
// *
// * start of child process handling (minus prefork)
// *
// *

// look for any dead children, and clean them up

void mopup_afterkids() {
    pid_t pid;
    int stat_val;
    while (true) {
        pid = waitpid(-1, &stat_val, WNOHANG);
        if (pid < 1) {
            break;
        }
        deletechild((int) pid);
    }
}

// get a free slot in out PID list, if there is one - return -1 if not

int getchildslot() {
    int i;
    for (i = 0; i < o.max_children; i++) {
        if (childrenpids[i] == -1) {
            return i;
        }
    }
    return -1;
}

// add the given child, including FD & PID, to the given slot in our lists

void addchild(int pos, int fd, pid_t child_pid) {
    childrenpids[pos] = (int) child_pid;
    childrenstates[pos] = 4; // busy waiting for init
    numchildren++;
    busychildren++;
    waitingfor++;
    pids[pos].fd = fd;
    UDSocket* sock = new UDSocket(fd);
    childsockets[pos] = sock;
}

// kill give number of non-busy children

void cullchildren(int num) {
#ifdef MIND_DEBUG
    std::cout << "culling childs:" << num << std::endl;
#endif
    int i;
    int count = 0;
    for (i = o.max_children - 1; i >= 0; i--) {
        if (childrenstates[i] == 0) {
            kill(childrenpids[i], SIGTERM);
            count++;
            childrenstates[i] = -2; // dieing
            numchildren--;
            delete childsockets[i];
            childsockets[i] = NULL;
            pids[i].fd = -1;
            if (count >= num) {
                break;
            }
        }
    }
}

// send SIGTERM to all child processes

void kill_allchildren() {
#ifdef MIND_DEBUG
    std::cout << "killing all childs:" << std::endl;
#endif
    for (int i = o.max_children - 1; i >= 0; i--) {
        if (childrenstates[i] >= 0) {
            kill(childrenpids[i], SIGTERM);
            childrenstates[i] = -2; // dieing
            numchildren--;
            delete childsockets[i];
            childsockets[i] = NULL;
            pids[i].fd = -1;
        }
    }
}

// send SIGHUP to all child processes

void hup_allchildren() {
#ifdef MIND_DEBUG
    std::cout << "huping all childs:" << std::endl;
#endif
    for (int i = o.max_children - 1; i >= 0; i--) {
        if (childrenstates[i] >= 0) {
            kill(childrenpids[i], SIGHUP);
        }
    }
}

// attempt to receive the message from the child's send_readystatus call

bool check_kid_readystatus(int tofind) {
    bool found = false;
    char *buf = new char[5];
    int rc = -1; // for compiler warnings
    for (int f = 0; f < o.max_children; f++) {

        if (tofind < 1) {
            break; // no point looping through all if all found
        }
        if (pids[f].fd == -1) {
            continue;
        }
        if ((pids[f].revents & POLLIN) > 0) {
            if (childrenstates[f] < 0) {
                tofind--;
                continue;
            }
            try {
                rc = childsockets[f]->getLine(buf, 4, 100, true);
            } catch (std::exception & e) {
                kill(childrenpids[f], SIGTERM);
                deletechild(childrenpids[f]);
                tofind--;
                continue;
            }
            if (rc > 0) {
                if (buf[0] == '2') {
                    if (childrenstates[f] == 4) {
                        waitingfor--;
                    }
                    childrenstates[f] = 0;
                    busychildren--;
                    tofind--;
                }
            } else { // child -> parent communications failure so kill it
                kill(childrenpids[f], SIGTERM);
                deletechild(childrenpids[f]);
                tofind--;
            }
        }
        if (childrenstates[f] == 0) {
            found = true;
        } else {
            found = false;
        }
    }
    // if unbusy found then true otherwise false
    delete[]buf;
    return found;
}

// remove child from our PID/FD and slot lists

void deletechild(int child_pid) {
    int i;
    for (i = 0; i < o.max_children; i++) {
        if (childrenpids[i] == child_pid) {
            childrenpids[i] = -1;
            // Delete a busy child
            if (childrenstates[i] == 1)
                busychildren--;
            // Delete a child which isn't "ready" yet
            if (childrenstates[i] == 4) {
                busychildren--;
                waitingfor--;
            }
            // Common code for any non-"culled" child
            if (childrenstates[i] != -2) {
                numchildren--;
                delete childsockets[i];
                childsockets[i] = NULL;
                pids[i].fd = -1;
            }
            childrenstates[i] = -1; // unused
            break;
        }
    }
    // never should happen that passed pid is not known,
    // unless its the logger or url cache process, in which case we
    // don't want to do anything anyway. and this can only happen
    // when shutting down or restarting.
}

// get the index of the first non-busy child

int getfreechild() { // check that there is 1 free done
    // before calling
    int i;
    for (i = 0; i < o.max_children; i++) {
        if (childrenstates[i] == 0) { // not busy (free)
            return i;
        }
    }
    return -1;
}

// tell given child process to accept an incoming connection

void tellchild_accept(int num, int whichsock) {
    // include server socket number in message
    try {
        childsockets[num]->writeToSockete((char*) & whichsock, 1, 0, 5, true);
    } catch (std::exception & e) {
        kill(childrenpids[num], SIGTERM);
        deletechild(childrenpids[num]);
        return;
    }

    // check for response from child
    char buf;
    try {
        childsockets[num]->readFromSocket(&buf, 1, 0, 5, false, true);
    } catch (std::exception & e) {
        kill(childrenpids[num], SIGTERM);
        deletechild(childrenpids[num]);
        return;
    }
    // no need to check what it actually contains,
    // as the very fact the child sent something back is a good sign
    busychildren++;
    childrenstates[num] = 1; // busy
}


// *
// *
// * end of child process handling code
// *
// *


// *
// *
// * logger, IP list and URL cache main loops
// *
// *

int url_list_listener(bool logconerror) {
#ifdef MIND_DEBUG
    std::cout << "url listener started" << std::endl;
#endif
    if (!drop_priv_completely()) {
        return 1; //error
    }
    UDSocket* ipcpeersock = NULL; // the socket which will contain the ipc connection
    int rc, ipcsockfd;
    char *logline = new char[32000];
    char reply;
    DynamicURLList urllist;
#ifdef MIND_DEBUG
    std::cout << "setting url list size-age:" << o.url_cache_number << "-" << o.url_cache_age << std::endl;
#endif
    urllist.setListSize(o.url_cache_number, o.url_cache_age);
    ipcsockfd = urllistsock.getFD();
#ifdef MIND_DEBUG
    std::cout << "url ipcsockfd:" << ipcsockfd << std::endl;
#endif

    fd_set fdSet; // our set of fds (only 1) that select monitors for us
    fd_set fdcpy; // select modifes the set so we need to use a copy
    FD_ZERO(&fdSet); // clear the set
    FD_SET(ipcsockfd, &fdSet); // add ipcsock to the set

#ifdef MIND_DEBUG
    std::cout << "url listener entering select()" << std::endl;
#endif
    while (true) { // loop, essentially, for ever

        fdcpy = fdSet; // take a copy

        rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, NULL); // block
        // until something happens
#ifdef MIND_DEBUG
        std::cout << "url listener select returned" << std::endl;
#endif
        if (rc < 0) { // was an error
            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
            if (logconerror) {
                log.writeToLog(1, "%s", "url ipc rc<0. (Ignorable)");
            }
            continue;
        }
        if (FD_ISSET(ipcsockfd, &fdcpy)) {
#ifdef MIND_DEBUG
            std::cout << "received an url request" << std::endl;
#endif
            ipcpeersock = urllistsock.accept();
            if (ipcpeersock->getFD() < 0) {
                delete ipcpeersock;
                if (logconerror) {
#ifdef MIND_DEBUG
                    std::cout << "Error accepting url ipc. (Ignorable)" << std::endl;
#endif
                    log.writeToLog(1, "%s", "Error accepting url ipc. (Ignorable)");
                }
                continue; // if the fd of the new socket < 0 there was error
                // but we ignore it as its not a problem
            }
            try {
                rc = ipcpeersock->getLine(logline, 32000, 3, true); // throws on err
            } catch (std::exception & e) {
                delete ipcpeersock; // close the connection
                if (logconerror) {
#ifdef MIND_DEBUG
                    std::cout << "Error reading url ipc. (Ignorable)" << std::endl;
                    std::cerr << e.what() << std::endl;
#endif
                    log.writeToLog(1, "%s", "Error reading url ipc. (Ignorable)");
                    log.writeToLog(1, "%s", e.what());
                }
                continue;
            }
            // check the command type
            // f: flush the cache
            // g: add a URL to the cache
            // everything else: search the cache
            // n.b. we use command characters with ASCII encoding
            // > 100, because we can have up to 99 filter groups, and
            // group no. plus 1 is the first character in the 'everything else'
            // case.
            if (logline[0] == 'f') {
                delete ipcpeersock; // close the connection
                urllist.flush();
#ifdef MIND_DEBUG
                std::cout << "url FLUSH request" << std::endl;
#endif
                continue;
            }
            if (logline[0] == 'g') {
                delete ipcpeersock; // close the connection
                urllist.addEntry(logline + 2, logline[1] - 1);
                continue;
            }
            if (urllist.inURLList(logline + 1, logline[0] - 1)) {
                reply = 'Y';
            } else {
                reply = 'N';
            }
            try {
                ipcpeersock->writeToSockete(&reply, 1, 0, 6);
            } catch (std::exception & e) {
                delete ipcpeersock; // close the connection
                if (logconerror) {
                    log.writeToLog(1, "%s", "Error writing url ipc. (Ignorable)");
                    log.writeToLog(1, "%s", e.what());
                }
                continue;
            }
            delete ipcpeersock; // close the connection
#ifdef MIND_DEBUG
            std::cout << "url list reply: " << reply << std::endl;
#endif
            continue; // go back to listening
        }
    }
    delete[]logline;
    urllistsock.close(); // be nice and neat
    return 1; // It is only possible to reach here with an error
}

int ip_list_listener(std::string stat_location, bool logconerror) {
#ifdef MIND_DEBUG
    std::cout << "ip listener started" << std::endl;
#endif
    if (!drop_priv_completely()) {
        return 1; //error
    }
    UDSocket *ipcpeersock;
    int rc, ipcsockfd;
    char* inbuff = new char[16];

    // pass in size of list, and max. age of entries (7 days, apparently)
    DynamicIPList iplist(o.max_ips, 604799);

    ipcsockfd = iplistsock.getFD();

    unsigned long int ip;
    char reply;
    struct in_addr inaddr;

    struct timeval sleep; // used later on for a short sleep
    sleep.tv_sec = 180;
    sleep.tv_usec = 0;
    struct timeval scopy; // copy to use as select() can modify

    int maxusage = 0; // usage statistics:
    // current & highest no. of concurrent IPs using the filter

    double elapsed = 0; // keep a 3 minute counter so license statistics
    time_t before; // are written even on busy networks (don't rely on timeout)

    fd_set fdSet; // our set of fds (only 1) that select monitors for us
    fd_set fdcpy; // select modifes the set so we need to use a copy
    FD_ZERO(&fdSet); // clear the set
    FD_SET(ipcsockfd, &fdSet); // add ipcsock to the set

#ifdef MIND_DEBUG
    std::cout << "ip listener entering select()" << std::endl;
#endif
    scopy = sleep;
    // loop, essentially, for ever
    while (true) {
        fdcpy = fdSet; // take a copy
        before = time(NULL);
        rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, &scopy); // block until something happens
        elapsed += difftime(time(NULL), before);
#ifdef MIND_DEBUG
        std::cout << "ip listener select returned: " << rc << ", 3 min timer: " << elapsed << ", scopy: " << scopy.tv_sec << " " << scopy.tv_usec << std::endl;
#endif
        if (rc < 0) { // was an error
            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
            if (logconerror) {
                log.writeToLog(1, "ip ipc rc<0. (Ignorable)");
            }
            continue;
        }
        if (rc == 0 || elapsed >= 180) {
#ifdef MIND_DEBUG
            std::cout << "ips in list: " << iplist.getNumberOfItems() << std::endl;
            std::cout << "purging old ip entries" << std::endl;
            std::cout << "ips in list: " << iplist.getNumberOfItems() << std::endl;
#endif
            // should only get here after a timeout
            iplist.purgeOldEntries();
            // write usage statistics
            int currusage = iplist.getNumberOfItems();
            if (currusage > maxusage)
                maxusage = currusage;
            String usagestats;
            usagestats += String(currusage) + "\n" + String(maxusage) + "\n";
#ifdef MIND_DEBUG
            std::cout << "writing usage stats: " << currusage << " " << maxusage << std::endl;
#endif
            int statfd = open(stat_location.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (statfd > 0) {
                write(statfd, usagestats.toCharArray(), usagestats.length());
            }
            close(statfd);
            // reset sleep timer
            scopy = sleep;
            elapsed = 0;
            // only skip back to top of loop if there was a genuine timeout
            if (rc == 0)
                continue;
        }
        if (FD_ISSET(ipcsockfd, &fdcpy)) {
#ifdef MIND_DEBUG
            std::cout << "received an ip request" << std::endl;
#endif
            ipcpeersock = iplistsock.accept();
            if (ipcpeersock->getFD() < 0) {
                delete ipcpeersock;
                if (logconerror) {
#ifdef MIND_DEBUG
                    std::cout << "Error accepting ip ipc. (Ignorable)" << std::endl;
#endif
                    log.writeToLog(1, "Error accepting ip ipc. (Ignorable)");
                }
                continue; // if the fd of the new socket < 0 there was error
                // but we ignore it as its not a problem
            }
            try {
                rc = ipcpeersock->getLine(inbuff, 16, 3); // throws on err
            } catch (std::exception& e) {
                delete ipcpeersock;
                if (logconerror) {
#ifdef MIND_DEBUG
                    std::cout << "Error reading ip ipc. (Ignorable)" << std::endl;
#endif
                    log.writeToLog(1, "Error reading ip ipc. (Ignorable)");
                }
                continue;
            }
#ifdef MIND_DEBUG
            std::cout << "recieved ip:" << inbuff << std::endl;
#endif
            inet_aton(inbuff, &inaddr);
            ip = inaddr.s_addr;
            // is the ip in our list? this also takes care of adding it if not.
            if (iplist.inList(ip))
                reply = 'Y';
            else
                reply = 'N';
            try {
                ipcpeersock->writeToSockete(&reply, 1, 0, 6);
            } catch (std::exception& e) {
                delete ipcpeersock;
                if (logconerror) {
#ifdef MIND_DEBUG
                    std::cout << "Error writing ip ipc. (Ignorable)" << std::endl;
#endif
                    log.writeToLog(1, "Error writing ip ipc. (Ignorable)");
                }
                continue;
            }
            delete ipcpeersock; // close the connection
#ifdef MIND_DEBUG
            std::cout << "ip list reply: " << reply << std::endl;
#endif
            continue; // go back to listening
        }
    }
    delete[] inbuff;
    iplistsock.close(); // be nice and neat
    return 1; // It is only possible to reach here with an error
}


// *
// *
// * end logger, IP list and URL cache code
// *
// *


// Does lots and lots of things - forks off url cache & logger processes, preforks child processes for connection handling, does tidying up on exit
// also handles the various signalling options MinD supports (reload config, flush cache, kill all processes etc.)

int fc_controlit() {
    int rc, fds;

    o.lm.garbageCollect();

    // allocate & create our server sockets
    serversocketcount = o.filter_ip.size();

    serversockets.reset(serversocketcount);
    int *serversockfds = serversockets.getFDAll();

    for (int i = 0; i < serversocketcount; i++) {
        // if the socket fd is not +ve then the socket creation failed
        if (serversockfds[i] < 0) {
            log.writeToLog(1, "Error creating server socket %d", i);
            return 1;
        }
    }


    if (o.no_logger) {
        loggersock.close();
    } else {
        loggersock.reset();
    }
    if (o.url_cache_number > 0) {
        urllistsock.reset();
    } else {
        urllistsock.close();
    }
    if (o.max_ips > 0) {
        iplistsock.reset();
    } else {
        iplistsock.close();
    }

    pid_t loggerpid = 0; // to hold the logging process pid
    pid_t urllistpid = 0; // url cache process id
    pid_t iplistpid = 0; // ip cache process id

    if (!o.no_logger) {
        if (loggersock.getFD() < 0) {
            log.writeToLog(1, "%s", "Error creating ipc socket");
            return 1;
        }
    }

    // Made unconditional such that we have root privs when creating pidfile & deleting old IPC sockets
    // PRA 10-10-2005
    /*bool needdrop = false;

    if (o.filter_port < 1024) {*/
#ifdef MIND_DEBUG
    std::cout << "seteuiding for low port binding/pidfile creation" << std::endl;
#endif
    //needdrop = true;
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t) - 1, o.root_user);
#else
    rc = seteuid(o.root_user);
#endif
    if (rc == -1) {
        log.writeToLog(1, "%s", "Unable to seteuid() to bind filter port.");
#ifdef MIND_DEBUG
        std::cerr << "Unable to seteuid() to bind filter port." << std::endl;
#endif
        return 1;
    }
    //}

    // we have to open/create as root before drop privs
    int pidfilefd = sysv_openpidfile(o.pid_filename);
    if (pidfilefd < 0) {
        log.writeToLog(1, "%s", "Error creating/opening pid file.");
        std::cerr << "Error creating/opening pid file:" << o.pid_filename << std::endl;
        return 1;
    }

    // we expect to find a valid filter ip 0 specified in conf if multiple IPs are in use.
    // if we don't find one, bind to any, as per old behaviour.
    if (o.filter_ip[0].length() > 6) {
        if (serversockets.bindAll(o.filter_ip, o.filter_port)) {
            if (!is_daemonised) {
                std::cerr << "Error binding server socket (is something else running on the filter port and ip?" << std::endl;
            }
            log.writeToLog(1, "Error binding server socket (is something else running on the filter port and ip?");
            return 1;
        }
    } else {
        // listen/bind to a port on any interface
        if (serversockets.bindSingle(o.filter_port)) {

            log.writeToLog(1, "Error binding server socket: [%d] (%s)", o.filter_port, strerror(errno));
            return 1;
        }
    }

    // Made unconditional for same reasons as above
    //if (needdrop) {
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t) - 1, o.proxy_user);
#else
    rc = seteuid(o.proxy_user); // become low priv again
#endif
    if (rc == -1) {
        log.writeToLog(1, "Unable to re-seteuid()");
#ifdef MIND_DEBUG
        std::cerr << "Unable to re-seteuid()" << std::endl;
#endif
        return 1; // seteuid failed for some reason so exit with error
    }
    //}

    // Needs deleting if its there
    unlink(o.ipc_filename.c_str()); // this would normally be in a -r situation.
    // disabled as requested by Christopher Weimann <csw@k12hq.com>
    // Fri, 11 Feb 2005 15:42:28 -0500
    // re-enabled temporarily
    unlink(o.urlipc_filename.c_str());
    unlink(o.ipipc_filename.c_str());

    if (!o.no_logger) {
        if (loggersock.bind((char *) o.ipc_filename.c_str())) { // bind to file
            log.writeToLog(1, "Error binding ipc server file (try using the SysV to stop MinD then try starting it again or doing an 'rm %s').", o.ipc_filename.c_str());
            return 1;
        }
        if (loggersock.listen(256)) { // set it to listen mode with a kernel
            // queue of 256 backlog connections
            if (!is_daemonised) {
                std::cerr << "Error listening to ipc server file" << std::endl;
            }
            log.writeToLog(1, "Error listening to ipc server file");
            return 1;
        }
    }

    if (o.url_cache_number > 0) {
        if (urllistsock.bind((char *) o.urlipc_filename.c_str())) { // bind to file
            log.writeToLog(1, "Error binding urllistsock server file (try using the SysV to stop MinD then try starting it again or doing an 'rm %s').", o.urlipc_filename.c_str());
            return 1;
        }
        if (urllistsock.listen(256)) { // set it to listen mode with a kernel
            // queue of 256 backlog connections
            log.writeToLog(1, "Error listening to url ipc server file");
            return 1;
        }
    }

    if (o.max_ips > 0) {
        if (iplistsock.bind(o.ipipc_filename.c_str())) { // bind to file
            log.writeToLog(1, "Error binding iplistsock server file (try using the SysV to stop MinD then try starting it again or doing an 'rm %s').", o.ipipc_filename.c_str());
            return 1;
        }
        if (iplistsock.listen(256)) { // set it to listen mode with a kernel
            // queue of 256 backlog connections
            log.writeToLog(1, "Error listening to ip ipc server file");
            return 1;
        }
    }

    if (serversockets.listenAll(256)) { // set it to listen mode with a kernel
        // queue of 256 backlog connections
        log.writeToLog(1, "Error listening to server socket");
        return 1;
    }

    if (!daemonise()) { // become a detached daemon
        log.writeToLog(1, "Error daemonising");
        return 1;
    }

    // this has to be done after daemonise to ensure we get the correct PID.
    rc = sysv_writepidfile(pidfilefd); // also closes the fd
    if (rc != 0) {
        log.writeToLog(1, "Error writing to the mind.pid file: %s", strerror(errno));
        return false;
    }
    // We are now a daemon so all errors need to go in the syslog, rather
    // than being reported on screen as we've detached from the console and
    // trying to write to stdout will not be nice.

    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL)) { // ignore SIGPIPE so we can handle
        // premature disconections better
        log.writeToLog(1, "%s", "Error ignoring SIGPIPE");
        return (1);
    }
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGHUP, &sa, NULL)) { // ignore HUP
        log.writeToLog(1, "%s", "Error ignoring HUP");
        return (1);
    }

    // Next thing we need to do is to split into two processes - one to
    // handle incoming TCP connections from the clients and one to handle
    // incoming UDS ipc from our forked children.  This helps reduce
    // bottlenecks by not having only one select() loop.
    if (!o.no_logger) {

        loggerpid = fork(); // make a child processes copy of self to be logger

        if (loggerpid == 0) {
            serversockets.deleteAll();
            delete[] serversockfds;
            urllistsock.close();
            strcpy(procName, "mind_logging_process");
            if (!drop_priv_completely()) {
                return 1; //error
            }
            log_listener();
#ifdef MIND_DEBUG
            std::cout << "Log listener exiting" << std::endl;
#endif
            _exit(0); // is reccomended for child and daemons to use this instead
        }
    }

    // Same for URL list listener
    if (o.url_cache_number > 0) {
        urllistpid = fork();
        if (urllistpid == 0) { // ma ma!  i am the child
            serversockets.deleteAll(); // we don't need our copy of this so close it
            delete[] serversockfds;
            if (!o.no_logger) {
                loggersock.close(); // we don't need our copy of this so close it
            }
            url_list_listener(o.logconerror);
#ifdef MIND_DEBUG
            std::cout << "URL List listener exiting" << std::endl;
#endif
            _exit(0); // is reccomended for child and daemons to use this instead
        }
    }

    // and for IP list listener
    if (o.max_ips > 0) {
        iplistpid = fork();
        if (iplistpid == 0) { // ma ma!  i am the child
            serversockets.deleteAll(); // we don't need our copy of this so close it
            delete[] serversockfds;
            if (!o.no_logger) {
                loggersock.close(); // we don't need our copy of this so close it
            }
            ip_list_listener(log.getStatLogFilename(), o.logconerror);
#ifdef MIND_DEBUG
            std::cout << "IP List listener exiting" << std::endl;
#endif
            _exit(0); // is reccomended for child and daemons to use this instead
        }
    }

    // I am the parent process here onwards.

#ifdef MIND_DEBUG
    std::cout << "Parent process created children" << std::endl;
#endif

    if (o.url_cache_number > 0) {
        urllistsock.close(); // we don't need our copy of this so close it
    }
    if (!o.no_logger) {
        loggersock.close(); // we don't need our copy of this so close it
    }
    if (o.max_ips > 0) {
        iplistsock.close();
    }

    memset(&sa, 0, sizeof (sa));
    if (!o.soft_restart) {
        sa.sa_handler = &sig_term; // register sig_term as our handler
    } else {
        sa.sa_handler = &sig_termsafe;
    }
    if (sigaction(SIGTERM, &sa, NULL)) { // when the parent process gets a
        // sigterm we need to kill our
        // children which this will do,
        // then we need to exit
        log.writeToLog(1, "Error registering SIGTERM handler");
        return (1);
    }

    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = &sig_hup; // register sig_hup as our handler
    if (sigaction(SIGHUP, &sa, NULL)) { // when the parent process gets a
        // sighup we need to kill our
        // children which this will do,
        // then we need to read config
        log.writeToLog(1, "Error registering SIGHUP handler");
        return (1);
    }

    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = &sig_usr1; // register sig_usr1 as our handler
    if (sigaction(SIGUSR1, &sa, NULL)) { // when the parent process gets a
        // sigusr1 we need to hup our
        // children to make them exit
        // then we need to read fg config
        log.writeToLog(1, "Error registering SIGUSR handler");
        return (1);
    }

#ifdef ENABLE_SEGV_BACKTRACE
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = &sig_segv;
    if (sigaction(SIGSEGV, &sa, NULL)) {
        log.writeToLog(1, "Error registering SIGSEGV handler");
        return 1;
    }
#endif

#ifdef MIND_DEBUG
    std::cout << "Parent process sig handlers done" << std::endl;
#endif

    numchildren = 0; // to keep count of our children
    busychildren = 0; // to keep count of our children
    int freechildren = 0; // to keep count of our children

    childrenpids = new int[o.max_children]; // so when one exits we know who
    childrenstates = new int[o.max_children]; // so we know what they're up to
    childsockets = new UDSocket* [o.max_children];
    fds = o.max_children + serversocketcount;

    pids = new struct pollfd[fds];

    int i;

    time_t tnow;
    time_t tmaxspare;

    time(&tmaxspare);

#ifdef MIND_DEBUG
    std::cout << "Parent process pid structs allocated" << std::endl;
#endif

    // store child fds...
    for (i = 0; i < o.max_children; i++) {
        childrenpids[i] = -1;
        childrenstates[i] = -1;
        pids[i].fd = -1;
        pids[i].events = POLLIN;

    }
    // ...and server fds
    for (i = o.max_children; i < fds; i++) {
        pids[i].fd = serversockfds[i - o.max_children];
        pids[i].events = POLLIN;
    }

#ifdef MIND_DEBUG
    std::cout << "Parent process pid structs zeroed" << std::endl;
#endif

    failurecount = 0; // as we don't exit on an error with select()
    // due to the fact that these errors do happen
    // every so often on a fully working, but busy
    // system, we just watch for too many errors
    // consecutivly.

    waitingfor = 0;
    rc = prefork(o.min_children);

    sleep(1); // need to allow some of the forks to complete

#ifdef MIND_DEBUG
    std::cout << "Parent process preforked rc:" << rc << std::endl;
    std::cout << "Parent process pid:" << getpid() << std::endl;
#endif

    if (rc < 0) {
        ttg = true;
        log.writeToLog(1, "%s", "Error creating initial fork pool - exiting...");
    }

    int tofind;
    reloadconfig = false;

    log.writeToLog(0, "Started sucessfully.");

    while (failurecount < 30 && !ttg && !reloadconfig) {

        // loop, essentially, for ever until 30
        // consecutive errors in which case something
        // is badly wrong.
        // OR, its timetogo - got a sigterm
        // OR, we need to exit to reread config
        if (gentlereload) {
#ifdef MIND_DEBUG
            std::cout << "gentle reload activated" << std::endl;
#endif
            o.deleteFilterGroups();
            if (!o.readFilterGroupConf()) {
                reloadconfig = true; // filter groups problem so lets
                // try and reload entire config instead
                // if that fails it will bomb out
            } else {
                if (o.use_filter_groups_list) {
                    o.filter_groups_list.reset();
                    if (!o.doReadItemList(o.filter_groups_list_location.c_str(), &(o.filter_groups_list), "filtergroupslist", true))
                        reloadconfig = true; // filter groups problem...
                }
                if (!reloadconfig) {
                    o.deletePlugins(o.csplugins);
                    if (!o.loadCSPlugins())
                        reloadconfig = true; // content scan plugs problem
                    if (!reloadconfig) {
                        o.deletePlugins(o.authplugins);
                        if (!o.loadAuthPlugins())
                            reloadconfig = true; // auth plugs problem
                    }
                    if (!reloadconfig) {
                        hup_allchildren();
                        o.lm.garbageCollect();
                        prefork(o.min_children);
                        gentlereload = false;
                        // everything ok - no full reload needed
                        // clear gentle reload flag for next run of the loop
                    }
                }
            }
            flush_urlcache();
            continue;
        }

        // Lets take the opportunity to clean up our dead children if any
        for (i = 0; i < fds; i++) {
            pids[i].revents = 0;
        }
        mopup_afterkids();
        rc = poll(pids, fds, 60 * 1000);
        mopup_afterkids();

        if (rc < 0) { // was an error
#ifdef MIND_DEBUG
            std::cout << "errno:" << errno << " " << strerror(errno) << std::endl;
#endif

            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
            if (o.logconerror)
                log.writeToLog(1, "Error polling child process sockets: %s", strerror(errno));
            failurecount++; // log the error/failure
            continue; // then continue with the looping
        }

        tofind = rc;
        if (rc > 0) {
            for (i = o.max_children; i < fds; i++) {
                if (pids[i].revents) {
                    tofind--;
                }
            }
        }

        if (tofind > 0) {
            check_kid_readystatus(tofind);
            mopup_afterkids();
        }

        freechildren = numchildren - busychildren;

#ifdef MIND_DEBUG
        std::cout << "numchildren:" << numchildren << std::endl;
        std::cout << "busychildren:" << busychildren << std::endl;
        std::cout << "freechildren:" << freechildren << std::endl;
        std::cout << "waitingfor:" << waitingfor << std::endl << std::endl;
#endif

        if (rc > 0) {
            for (i = o.max_children; i < fds; i++) {
                if ((pids[i].revents & POLLIN) > 0) {
                    // socket ready to accept() a connection
                    failurecount = 0; // something is clearly working so reset count
                    if (freechildren < 1 && numchildren < o.max_children) {
                        if (waitingfor == 0) {
                            int num = o.prefork_children;
                            if ((o.max_children - numchildren) < num)
                                num = o.max_children - numchildren;
                            if (o.logchildprocs)
                                log.writeToLog(1, "Under load - Spawning %d process(es)", num);
                            rc = prefork(num);
                            if (rc < 0) {
                                log.writeToLog(1, "Error forking %d extra process(es).", num);
                                failurecount++;
                            }
                        } else
                            usleep(1000);
                        continue;
                    }
                    if (freechildren > 0) {
#ifdef MIND_DEBUG
                        std::cout << "telling child to accept " << (i - o.max_children) << std::endl;
#endif
                        int childnum = getfreechild();
                        if (childnum < 0) {
                            // Oops! weren't actually any free children.
                            // Not sure why as yet, but it seems this can
                            // sometimes happen. :(  PRA 2009-03-11
                            log.writeToLog(-1,
                                    "No free children from getfreechild(): numchildren = %d, busychildren = %d, waitingfor = %d",
                                    numchildren, busychildren, waitingfor
                                    );
                            freechildren = 0;
                            usleep(1000);
                        } else {
                            tellchild_accept(childnum, i - o.max_children);
                            --freechildren;
                        }
                    } else {
                        usleep(1000);
                    }
                } else if (pids[i].revents) {
                    ttg = true;
                    log.writeToLog(1, "Error with main listening socket.  Exiting.");
                    break;
                }
            }
            if (ttg)
                break;
        }

        if (freechildren < o.minspare_children && (waitingfor == 0) && numchildren < o.max_children) {
            if (o.logchildprocs)
                log.writeToLog(1, "Fewer than %d free children - Spawning %d process(es)", o.minspare_children, o.prefork_children);
            rc = prefork(o.prefork_children);
            if (rc < 0) {
                log.writeToLog(1, "Error forking preforkchildren extra processes.");
                failurecount++;
            }
        }

        if (freechildren <= o.maxspare_children) {
            time(&tmaxspare);
        }
        if (freechildren > o.maxspare_children) {
            time(&tnow);
            if ((tnow - tmaxspare) > (2 * 60)) {
                if (o.logchildprocs)
                    log.writeToLog(1, "More than %d free children - Killing %d process(es)", o.maxspare_children, freechildren - o.maxspare_children);
                cullchildren(freechildren - o.maxspare_children);
            }
        }
    }
    cullchildren(numchildren); // remove the fork pool of spare children
    for (int i = 0; i < o.max_children; i++) {
        if (pids[i].fd != -1) {
            delete childsockets[i];
            childsockets[i] = NULL;
        }
    }
    if (numchildren > 0) {
        hup_allchildren();
        sleep(2); // give them a small chance to exit nicely before we force
        // hmmmm I wonder if sleep() will get interupted by sigchlds?
    }
    if (numchildren > 0) {
        kill_allchildren();
    }
    // we might not giving enough time for defuncts to be created and then
    // mopped but on exit or reload config they'll get mopped up
    sleep(1);
    mopup_afterkids();

    delete[]childrenpids;
    delete[]childrenstates;
    delete[]childsockets;
    delete[]pids; // 4 deletes good, memory leaks bad

    if (failurecount >= 30) {
        log.writeToLog(1, "%s", "Exiting due to high failure count.");
#ifdef MIND_DEBUG
        std::cout << "Exiting due to high failure count." << std::endl;
#endif
    }
#ifdef MIND_DEBUG
    std::cout << "Main parent process exiting." << std::endl;
#endif

    serversockets.deleteAll();
    delete[] serversockfds; // be nice and neat

    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGTERM, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGTERM" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGTERM");
    }
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGHUP, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGHUP" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGHUP");
    }
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGUSR1" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGUSR1");
    }
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGPIPE, &sa, NULL)) { // restore sig handler
        // in child process
#ifdef MIND_DEBUG
        std::cerr << "Error resetting signal for SIGPIPE" << std::endl;
#endif
        log.writeToLog(1, "%s", "Error resetting signal for SIGPIPE");
    }

    if (sig_term_killall) {
        struct sigaction sa, oldsa;
        memset(&sa, 0, sizeof (sa));
        sa.sa_handler = SIG_IGN;
        sigaction(SIGTERM, &sa, &oldsa); // ignore sigterm for us
        kill(0, SIGTERM); // send everyone in this process group a TERM
        // which causes them to exit as the default action
        // but it also seems to send itself a TERM
        // so we ignore it
        sigaction(SIGTERM, &oldsa, NULL); // restore prev state
    }

    if (reloadconfig || ttg) {
        if (!o.no_logger)
            ::kill(loggerpid, SIGTERM); // get rid of logger
        if (o.url_cache_number > 0)
            ::kill(urllistpid, SIGTERM); // get rid of url cache
        if (o.max_ips > 0)
            ::kill(iplistpid, SIGTERM); // get rid of iplist
        return reloadconfig ? 2 : 0;
    }
    if (o.logconerror) {
        log.writeToLog(1, "%s", "Main parent process exiting.");
    }
    return 1; // It is only possible to reach here with an error
}

int log_listener() {

    UDSocket* ipcpeersock; // the socket which will contain the ipc connection
    int rc, ipcsockfd;
    long tv_sec = 0, tv_usec = 0;

#ifdef MIND_DEBUG
    std::cout << "log listener started" << std::endl;
#endif

    stRequestLog *requestLog;

    ipcsockfd = loggersock.getFD();

    fd_set fdSet; // our set of fds (only 1) that select monitors for us
    fd_set fdcpy; // select modifies the set so we need to use a copy
    FD_ZERO(&fdSet); // clear the set
    FD_SET(ipcsockfd, &fdSet); // add ipcsock to the set
    while (true) { // loop, essentially, for ever
        fdcpy = fdSet; // take a copy
        rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, NULL); // block

        // until something happens
        if (rc < 0) { // was an error
            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
            if (o.logconerror) {
                log.writeToLog(1, "ipc rc<0. (Ignorable)");
            }
            continue;
        }
        if (rc < 1) {
            if (o.logconerror) {
                log.writeToLog(1, "ipc rc<1. (Ignorable)");
            }
            continue;
        }
        if (FD_ISSET(ipcsockfd, &fdcpy)) {
#ifdef MIND_DEBUG
            std::cout << "received a log request" << std::endl;
#endif
            ipcpeersock = loggersock.accept();
            if (ipcpeersock->getFD() < 0) {
                delete ipcpeersock;
                if (o.logconerror) {
                    log.writeToLog(1, "Error accepting ipc. (Ignorable)");
                }
                continue; /* if the fd of the new socket < 0 there was error
                           * but we ignore it as its not a problem
                           */
            }

            // read in the various parts of the log string
            bool error = false;
            int itemcount = 0;

            log.stAccessLogResrv(&requestLog);

            while (itemcount < (o.log_user_agent ? 24 : 23)) {
                try {
                    char *logline = new char[8192];
                    rc = ipcpeersock->getLine(logline, 8192, 3, true); // throws on err

                    if (rc < 0) {
                        delete ipcpeersock;
                        log.writeToLog(1, "Error reading from log socket");
                        error = true;
                        break;
                    } else {
                        switch (itemcount) {
                            case 0:
                                requestLog->isAnException = (bool) atoi(logline);
                                break;
                            case 1:
                                requestLog->objectCategory = strdup(logline);
                                break;
                            case 2:
                                requestLog->blockeableContent = (bool) atoi(logline);
                                break;
                            case 3:
                                requestLog->objectWeight = atoi(logline);
                                break;
                            case 4:
                                requestLog->destinationURL = strdup(logline);
                                break;
                            case 5:
                                requestLog->actionReason = strdup(logline);
                                break;
                            case 6:
                                requestLog->httpMethod = strdup(logline);
                                break;
                            case 7:
                                requestLog->userName = strdup(logline);
                                break;
                            case 8:
                                strcpy(requestLog->userIPAddress, logline);
                                break;
                            case 9:
                                requestLog->destinationPort = atoi(logline);
                                break;
                            case 10:
                                requestLog->wasScanned = (bool) atoi(logline);
                                break;
                            case 11:
                                requestLog->isInfected = (bool) atoi(logline);
                                break;
                            case 12:
                                requestLog->contentModified = (bool) atoi(logline);
                                break;
                            case 13:
                                requestLog->urlModified = (bool) atoi(logline);
                                break;
                            case 14:
                                requestLog->headerModified = (bool) atoi(logline);
                                break;
                            case 15:
                                requestLog->objectSize = atoi(logline);
                                break;
                            case 16:
                                requestLog->filtergroup = atoi(logline);
                                requestLog->filtergroupName = strdup(o.fg[requestLog->filtergroup]->name.c_str());
                                break;
                            case 17:
                                requestLog->objectStatusCode = atoi(logline);
                                break;
                            case 18:
                                requestLog->cacheHit = (bool) atoi(logline);
                                break;
                            case 19:
                                requestLog->objectMimeType = strdup(logline);
                                break;
                            case 20:
                                tv_sec = atol(logline);
                                break;
                            case 21:
                                tv_usec = atol(logline);
                                break;
                            case 22:
                                requestLog->clientHost = strdup(logline);
                                break;
                            case 23:
                                requestLog->userAgent = strdup(logline);
                                break;
                        }
                    }
                    delete[]logline;
                } catch (std::exception & e) {
                    delete ipcpeersock;
                    if (o.logconerror)
                        log.writeToLog(1, "Error reading ipc. (Ignorable)");
                    error = true;
                    break;
                }
                itemcount++;
            }

            // don't build the log line if we couldn't read all the component parts
            if (error)
                continue;

            log.writeToAccessLog(requestLog);
            log.stAccessLogDrop(requestLog);
            requestLog = NULL;

#ifdef MIND_DEBUG
            std::cout << itemcount << " " << builtline << std::endl;
#endif
            delete ipcpeersock; // close the connection
            continue; // go back to listening
        }
    }
    // should never get here
    log.writeToLog(1, "Something wicked has ipc happened");

    loggersock.close();
    return 1; // It is only possible to reach here with an error
}
