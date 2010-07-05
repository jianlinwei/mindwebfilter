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

#include <cstdlib>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <cerrno>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef HAVE_CONFIG_H
#include "../mind_config.h"
#endif
#include "FatController.hpp"
#include "SysV.hpp"
#include "Logger.hpp"
#include "mind.hpp"

Logger log = Logger();
OptionContainer o;
bool is_daemonised;
char* procName;

// regexp used during URL decoding by HTTPHeader
// we want it compiled once, not every time it's used, so do so on startup
RegExp urldecode_re;

#ifdef HAVE_PCRE
// regexes used for embedded URL extraction by ContentFilter
RegExp absurl_re, relurl_re;
#endif

int main(int argc, char *argv[]) {

    is_daemonised = false;
    bool nodaemon = false;
    bool needreset = false;
    std::string configfile(__CONFFILE);
    srand(time(NULL));
    int rc;
    log.setInternalLogMask(511); /* Write everything to anyplace
                                  * until configuration file is loaded. */
    procName=argv[0];

#ifdef MIND_DEBUG
    std::cout << "Running in debug mode..." << std::endl;
#endif

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (unsigned int j = 1; j < strlen(argv[i]); j++) {
                char option = argv[i][j];
                bool dobreak = false;
                switch (option) {
                    case 'q':
                        read_config(configfile.c_str(), 0);
                        return sysv_kill(o.pid_filename);
                    case 'Q':
                        read_config(configfile.c_str(), 0);
                        sysv_kill(o.pid_filename, false);
                        // give the old process time to die
                        while (sysv_amirunning(o.pid_filename))
                            sleep(1);
                        unlink(o.pid_filename.c_str());
                        unlink(o.ipc_filename.c_str());
                        unlink(o.urlipc_filename.c_str());
                        // remember to reset config before continuing
                        needreset = true;
                        break;
                    case 's':
                        read_config(configfile.c_str(), 0);
                        return sysv_showpid(o.pid_filename);
                    case 'r':
                        read_config(configfile.c_str(), 0);
                        return sysv_hup(o.pid_filename);
                    case 'g':
                        read_config(configfile.c_str(), 0);
                        return sysv_usr1(o.pid_filename);
                    case 'v':
                        std::cout << "MinD " << PACKAGE_VERSION << std::endl << std::endl;
//TODO: Solve compilation problem
//                                << "Built with: " << MIND_CONFIGURE_OPTIONS << std::endl;
                        return 0;
                    case 'N':
                        nodaemon = true;
                        break;
                    case 'c':
                        if ((i + 1) < argc) {
                            configfile = argv[i + 1];
                            dobreak = true; // broken-ness of this option reported by Jason Gauthier 2006-03-09
                        } else {
                            std::cerr << "No config file specified!" << std::endl;
                            return 1;
                        }
                        break;
                    case 'h':
                        std::cout << "Usage: " << argv[0] << " [{-c ConfigFileName|-v|-P|-h|-N|-q|-s|-r|-g}]" << std::endl;
                        std::cout << "  -v gives the version number and build options." << std::endl;
                        std::cout << "  -h gives this message." << std::endl;
                        std::cout << "  -c allows you to specify a different configuration file location." << std::endl;
                        std::cout << "  -N Do not go into the background." << std::endl;
                        std::cout << "  -q causes MinD to kill any running copy." << std::endl;
                        std::cout << "  -Q kill any running copy AND start a new one with current options." << std::endl;
                        std::cout << "  -s shows the parent process PID and exits." << std::endl;
                        std::cout << "  -r closes all connections and reloads config files by issuing a HUP," << std::endl;
                        std::cout << "     but this does not reset the maxchildren option (amongst others)." << std::endl;
                        std::cout << "  -g gently restarts by not closing all current connections; only reloads" << std::endl
                                << "     filter group config files. (Issues a USR1)" << std::endl;
                        return 0;
                }
                if (dobreak) break; // skip to the next argument
            }
        }
    }

    // Set current locale for proper character conversion
    setlocale(LC_ALL, "");

    if (needreset) {
        o.reset();
    }

    read_config(configfile.c_str(), 2);

    if (sysv_amirunning(o.pid_filename)) {
        log.writeToLog(-1, "A copy of MIND is already running. Exiting.");
        return 1; // can't have two copies running!!
    }

    if (nodaemon) {
        o.no_daemon = 1;
    }

    if ((o.max_children + 6) > FD_SETSIZE) {
        log.writeToLog(1, "maxchildren option in mind.conf has a value too high.");
        return 1;
    }

    unsigned int rootuid; // prepare a struct for use later
    rootuid = geteuid();
    o.root_user = rootuid;

    struct passwd *st; // prepare a struct
    struct group *sg;

    // "daemongroup" option exists, but never used to be honoured. this is now
    // an important feature, however, because we need to be able to create temp
    // files with suitable permissions for scanning by AV daemons - we do this
    // by becoming a member of a specified AV group and setting group read perms
    if ((sg = getgrnam(o.daemon_group_name.c_str())) != 0) {
        o.proxy_group = sg->gr_gid;
    } else {
        log.writeToLog(1, "Unable to getgrnam(): %s", strerror(errno));
        return 1;
    }

    if ((st = getpwnam(o.daemon_user_name.c_str())) != 0) { // find uid for proxy user
        o.proxy_user = st->pw_uid;

        rc = setgid(o.proxy_group); // change to rights of proxy user group
        // i.e. low - for security
        if (rc == -1) {

            log.writeToLog(1, "Unable to setgid()");
            return 1; // setgid failed for some reason so exit with error
        }
#ifdef HAVE_SETREUID
        rc = setreuid((uid_t) - 1, st->pw_uid);
#else
        rc = seteuid(o.proxy_user); // need to be euid so can su back
        // (yes it negates but no choice)
#endif
        if (rc == -1) {
            log.writeToLog(1, "Unable to seteuid()");
            return 1; // seteuid failed for some reason so exit with error
        }
    } else {
        log.writeToLog(1, "Unable to getpwnam(). Does user %s exist?", o.daemon_user_name.c_str());
        return 1; // was unable to lockup the user id from passwd
        // for some reason, so exit with error
    }

    if (!o.no_logger) {
        if (!log.testLogs('I')){
            log.writeToLog(1, "Error opening/creating internal log file: %s", log.getInternalLogFilename());
            return 1;
        }
        if (!log.testLogs('R')){
            log.writeToLog(1, "Error opening/creating request log file: %s", log.getRequestLogFilename());
            return 1;
        }
        if (!log.testLogs('S')){
            log.writeToLog(1, "Error opening/creating statistic log file: %s", log.getStatLogFilename());
            return 1;
        }
    }

    urldecode_re.comp("%[0-9a-fA-F][0-9a-fA-F]"); // regexp for url decoding

#ifdef HAVE_PCRE
    // todo: these only work with PCRE enabled (non-greedy matching).
    // change them, or make them a feature for which you need PCRE?
    absurl_re.comp("[\"'](http|ftp)://.*?[\"']"); // find absolute URLs in quotes
    relurl_re.comp("(href|src)\\s*=\\s*[\"'].*?[\"']"); // find relative URLs in quotes
#endif

    // this is no longer a class, but the comment has been retained for historical reasons. PRA 03-10-2005
    //FatController f;  // Thomas The Tank Engine

    while (true) {
        rc = fc_controlit();
        // its a little messy, but I wanted to split
        // all the ground work and non-daemon stuff
        // away from the daemon class
        // However the line is not so fine.
        if (rc == 2) {

            // In order to re-read the conf files and create cache files
            // we need to become root user again

#ifdef HAVE_SETREUID
            rc = setreuid((uid_t) - 1, rootuid);
#else
            rc = seteuid(rootuid);
#endif
            if (rc == -1) {
                log.writeToLog(1, "Unable to seteuid() to read conf files.");
#ifdef MIND_DEBUG
                std::cerr << "Unable to seteuid() to read conf files." << std::endl;
#endif
                return 1;
            }
#ifdef MIND_DEBUG
            std::cout << "About to re-read conf file." << std::endl;
#endif
            o.reset();
            if (!o.read(configfile.c_str(), 2)) {
                log.writeToLog(1, "Error re-parsing the mind.conf file or other MinD configuration files");
#ifdef MIND_DEBUG
                std::cerr << "Error re-parsing the mind.conf file or other MinD configuration files" << std::endl;
#endif
                return 1;
                // OptionContainer class had an error reading the conf or
                // other files so exit with error
            }
#ifdef MIND_DEBUG
            std::cout << "conf file read." << std::endl;
#endif

            if (nodaemon) {
                o.no_daemon = 1;
            }

            while (waitpid(-1, NULL, WNOHANG) > 0) {
            } // mop up defunts

#ifdef HAVE_SETREUID
            rc = setreuid((uid_t) - 1, st->pw_uid);
#else
            rc = seteuid(st->pw_uid); // become low priv again
#endif

            if (rc == -1) {
                log.writeToLog(1, "Unable to re-seteuid()");
                return 1; // seteuid failed for some reason so exit with error
            }
            continue;
        }

        if (rc > 0) {
            log.writeToLog(1, "Exiting with error");
            return rc; // exit returning the error number
        }
        return 0; // exit without error
    }
}

// get the OptionContainer to read in the given configuration file
void read_config(const char *configfile, int type) {
    int rc = open(configfile, 0, O_RDONLY);
    if (rc < 0) {
        log.writeToLog(1, "Error opening %s", configfile);
        exit(1); // could not open conf file for reading, exit with error
    }
    close(rc);

    if (!o.read(configfile, type)) {
        log.writeToLog(0, "%s", "Error parsing the mind.conf file or other MinD configuration files");
        exit(1); // OptionContainer class had an error reading the conf or other files so exit with error
    }
}
