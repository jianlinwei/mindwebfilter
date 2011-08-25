/*  -*- mode: c++; coding: utf-8; c-file-style: "stroustrup"; -*-

    Copyright 2011 MinD development team.
    This file is part of MinD Blaster project.

    MinD Blaster project is free software:
    You can redistribute it and/or modify it under the terms of the
    GNU General Public License as published by the Free Software Foundation,
    either version 3 of the License, or (at your option) any later version.

    MinD Blaster is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MinD Blaster.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <string>
#include <iostream>
#include <getopt.h>
#include <string.h>
#include <stdexcept>
#include <signal.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <dirent.h>
#include <sched.h>

#include "main.hpp"
#include "ConfigurationManager.hpp"
#include "LogManager.hpp"
#include "lib/spserver/spporting.hpp"
#include "lib/spserver/sphttp.hpp"
#include "lib/spserver/sphttpmsg.hpp"
#include "lib/spserver/spdispatcher.hpp"
#include "lib/spserver/spioutils.hpp"
#include "RequestHandler.hpp"

using namespace std;

// Mind Global Objects.
CConfigurationManager globalConfig;
CInternalLog internalLog;
CTrafficLog trafficLog;

class CRequestFactory : public SP_HttpHandlerFactory {
public:

    CRequestFactory() {
    }

    virtual ~CRequestFactory() {
    }

    virtual SP_HttpHandler * create() const {
        return new CRequestHandler();
    }
};

/*
 * 
 */
int main(int argc, char **argv) {

    globalConfig.rootUID = geteuid();

    if (argc > 1)
        executeArgs(argc, argv);

    if (globalConfig.rootUID != 0) {
        cerr << "MinD server must be launched as root." << endl;
        abort();
    }

    globalConfig.readConfiguration(CONFIGURATION_FILE);
    internalLog.initialize(globalConfig);
    trafficLog.initialize(globalConfig);

    if (isRunning()) {
        internalLog.write(INFO_MESSAGE,
                "MinD Blaster is allready running with pid (%d).",
                isRunning());
        exit(EXIT_FAILURE);
    }

    if (!globalConfig.runForeground &&
            (
            globalConfig.internalLogOutputMask & (STD_LOG_MASK * INFO_MESSAGE)
            || globalConfig.internalLogOutputMask & (STD_LOG_MASK * WARNING_MESSAGE)
            || globalConfig.internalLogOutputMask & (STD_LOG_MASK * ERROR_MESSAGE)
            )) {
        cerr << "Warning: Internal log configuration is setted to write" << endl
                << "some messages to stdout but MinD is running as a daemon"
                << endl;

        if (globalConfig.internalLogOutputMask & (STD_LOG_MASK * INFO_MESSAGE)) {
            cerr << "* Changing log configuration mask for INFO messages." << endl;
            globalConfig.internalLogOutputMask -= (STD_LOG_MASK * INFO_MESSAGE);
        }

        if (globalConfig.internalLogOutputMask & (STD_LOG_MASK * WARNING_MESSAGE)) {
            cerr << "* Changing log configuration mask for WARNING messages." << endl;
            globalConfig.internalLogOutputMask -= (STD_LOG_MASK * WARNING_MESSAGE);
        }

        if (globalConfig.internalLogOutputMask & (STD_LOG_MASK * ERROR_MESSAGE)) {
            cerr << "* Changing log configuration mask for ERROR messages." << endl;
            globalConfig.internalLogOutputMask -= (STD_LOG_MASK * ERROR_MESSAGE);
        }
    }

    if (!globalConfig.runForeground)
        demonize();
    else
        globalConfig.pid = getpid(); // Set parent pid as server pid.

    createPidFile();

    nice(-20 + globalConfig.serverEngineCPUscheduling);
    setCPUaffinity();

    setProxyUserAndGroup();
    trapSignals();

    internalLog.write(INFO_MESSAGE,
            "MinD Blaster version %s started successfully.",
            APP_VERSION);

    if (globalConfig.logFastDump)
        internalLog.write(WARNING_MESSAGE,
            "Log fast dump is activated. this may cause a performance issue.");


    //while(1);
    //    sleep(30);

    const char * refusedMsg = "HTTP/1.1 500 Sorry, server is busy now!\r\n";

    SP_HttpHandlerAdapterFactory factory(new CRequestFactory());

    int listenFd = -1;
    if (0 == SP_IOUtils::tcpListen(globalConfig.serverNetworkListenAddress.c_str(),
            globalConfig.serverNetworkListenPort, &listenFd)) {
        SP_Dispatcher dispatcher(new SP_DefaultCompletionHandler(), globalConfig.serverEngineRequestQueueSize);
        dispatcher.dispatch();
        dispatcher.setTimeout(60);

        for (;;) {
            struct sockaddr_in addr;
            socklen_t socklen = sizeof ( addr);
            int fd = accept(listenFd, (struct sockaddr*) &addr, &socklen);

            if (fd > 0) {
                if (dispatcher.getSessionCount() >= globalConfig.serverEngineRequestQueueSize
                        || dispatcher.getReqQueueLength() >= globalConfig.serverEngineRequestQueueSize) {
                    write(fd, refusedMsg, strlen(refusedMsg));
                    close(fd);
                } else {
                    dispatcher.push(fd, factory.create());
                }
            } else {
                break;
            }
        }
    }

    removePidFile();

    return 0;
}

void showHelp(void) {
    cout << "MinD Blaster version " << APP_VERSION << endl
            << "High performance proxy and web adapter." << endl
            << "Usage: mind [OPTION]..." << endl << endl
            <<
            "Mandatory arguments to long options are mandatory for short options too."
            << endl << "  -h, --help                 display this help and exit" <<
            endl << "  -v, --version              output version information and exit"
            << endl <<
            "  -t, --test-config          test configuration files and exit" << endl
            << "  -c, --config-file=FILE     load a specified configuration file" <<
            endl << "  -r, --reload-config        reload all configuration files" <<
            endl << "  -f, --foreground           start server into the foreground" <<
            endl << "  -s, --stop                 stop any running copy of MinD" <<
            endl << endl;
}

void executeArgs(int argc, char **argv) {
    int currentIndex;

    while (1) {
        static struct option longOptions[] = {
            {"help", no_argument, 0, 'h'},
            {"version", no_argument, 0, 'v'},
            {"test-config", no_argument, 0, 't'},
            {"config-file", required_argument, 0, 'c'},
            {"reload-config", no_argument, 0, 'r'},
            {"foreground", no_argument, 0, 'f'},
            {"stop", no_argument, 0, 's'},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int optionIndex = 0;

        currentIndex =
                getopt_long(argc, argv, "hvtc:rfs", longOptions, &optionIndex);

        /* Detect the end of the options. */
        if (currentIndex == -1)
            break;

        switch (currentIndex) {
            case 0:
                if (longOptions[optionIndex].flag != 0)
                    break;
            case 'h':
                showHelp();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                cout << "MinD Blaster version " << APP_VERSION << endl;
                exit(EXIT_SUCCESS);
                break;
            case 't':
                cout << "Testing global configuration file: ";
                globalConfig.readConfiguration(CONFIGURATION_FILE);
                cout << "OK." << endl;
                exit(EXIT_SUCCESS);
                break;
            case 'c':
                if (!strlen(optarg)) {
                    cout << "option requires an argument -- "
                            << longOptions[optionIndex].name << endl;
                    exit(EXIT_SUCCESS);
                }
                printf("Loading alternative configuration file: '%s'\n", optarg);
                globalConfig.readConfiguration(optarg);
                break;
            case 'r':
                break;
            case 's':
                break;
            case 'f':
                globalConfig.runForeground = true;
                break;
            default:
                cout << "Try 'mind --help' for more information." << endl;
                exit(EXIT_FAILURE);
                break;
        }
    }

    if (optind < argc) {
        cout << "invalid option -- ";
        while (optind < argc)
            cout << argv[optind++];
        cout << endl;
        cout << "Try 'mind --help' for more information." << endl;
        exit(EXIT_FAILURE);
    }
}

void signalHandler(int signal) {
    switch (signal) {
        case SIGHUP:
            internalLog.write(INFO_MESSAGE, "Received SIGHUP signal.");
            break;
        case SIGTERM:
            internalLog.write(INFO_MESSAGE, "Received SIGTERM signal.");
            break;
        default:
            internalLog.write(INFO_MESSAGE, "Unhandled signal (%d) %s",
                    strsignal(signal));
            break;
    }
}

void demonize(void) {

    pid_t pid;

    pid = fork();
    if (pid < 0) {
        internalLog.write(ERROR_MESSAGE, "Unable to perform fork().");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    globalConfig.pid = setsid();

    if (globalConfig.pid < 0) {
        internalLog.write(ERROR_MESSAGE, "Unable to perform setsid().");
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        internalLog.write(ERROR_MESSAGE, "Unable to perform chdir(\"/\").");
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return;
}

pid_t isRunning(void) {
    DIR *dp;
    string pidFullPath;
    char buffer[10];
    ifstream pidFile;
    pidFile.open(globalConfig.pidFile.c_str(), ios::binary);
    if (!pidFile.is_open())
        return NULL;
    pidFile.read(buffer, 10);
    pidFile.close();
    pidFullPath = "/proc/";
    sprintf(buffer, "%d", atoi(buffer));
    pidFullPath.append(buffer);
    dp = opendir(pidFullPath.c_str());
    if (dp) {
        closedir(dp);
        return (pid_t) atoi(buffer);
    } else
        return NULL;
}

void removePidFile(void) {
    setreuid((uid_t) - 1, globalConfig.rootUID);
    seteuid(globalConfig.rootUID);
    if (unlink(globalConfig.pidFile.c_str()) != 0) {
        internalLog.write(WARNING_MESSAGE, "Unable to remove \"%s\" PID file.",
                globalConfig.pidFile.c_str());
    }
}

void createPidFile(void) {
    ofstream pidFile;
    pidFile.open(globalConfig.pidFile.c_str(), ios::out | ios::binary);

    if (!pidFile.is_open()) {
        internalLog.write(ERROR_MESSAGE, "Unable to create \"%s\" pid file.",
                globalConfig.pidFile.c_str());
        exit(EXIT_FAILURE);
    }
    char pidString[10];
    sprintf(pidString, "%d\n", globalConfig.pid);
    pidFile.write(pidString, strlen(pidString));
    pidFile.close();
}

void setProxyUserAndGroup(void) {

    if (setgid(getgrnam(globalConfig.runGroup.c_str())->gr_gid) == -1) {
        internalLog.write(ERROR_MESSAGE, "Unable to set group \"%s\".",
                globalConfig.runGroup.c_str());
        exit(EXIT_FAILURE);
    }

    if (seteuid(getpwnam(globalConfig.runUser.c_str())->pw_uid) == -1) {
        internalLog.write(ERROR_MESSAGE, "Unable to set user \"%s\".",
                globalConfig.runUser.c_str());
        exit(EXIT_FAILURE);
    }
}

void trapSignals(void) {
    signal(SIGHUP, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);
    signal(SIGQUIT, signalHandler);
}

void setCPUaffinity(void) {
    static cpu_set_t mask;
    CPU_ZERO(&mask);
    for (int i = 0; i <= 32; i++) {
        if (globalConfig.serverEngineCPUbinding[i]) {
            CPU_SET(i, &mask);
        }
    }
    sched_setaffinity(0, sizeof (mask), &mask);
}
