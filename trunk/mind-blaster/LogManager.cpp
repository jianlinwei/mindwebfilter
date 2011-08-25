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

#include <fstream>
#include <iostream>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>


#include "LogManager.hpp"

using namespace std;

CLogManager::CLogManager() {
}

CLogManager::~CLogManager() {
    if (this->logStream.is_open())
        this->logStream.close();
}

CInternalLog::CInternalLog() {
    strcpy(this->severityArray[0], "INFO");
    strcpy(this->severityArray[1], "WARNING");
    strcpy(this->severityArray[3], "ERROR");
}

CInternalLog::~CInternalLog() {
}

CTrafficLog::CTrafficLog() {
    this->memoryBuffer = 0;
    this->fastDump = false;
    this->memoryBufferBlock = NULL;
}

CTrafficLog::~CTrafficLog() {

}

bool CInternalLog::initialize(CConfigurationManager &config) {
    this->logFastDump = config.logFastDump;
    this->logFile = config.internalLogDir + "mind.log";
    this->internalLogOutputMask = config.internalLogOutputMask;
    this->fieldSeparator = config.logFieldSeparator.c_str()[0];
    this->endLine = config.logEnding.c_str()[0];
    this->logStream.open(this->logFile.c_str(), ios::out | ios::app | ios::binary);
    if (!this->logStream.is_open()) {
        cerr << "An error has occurred while trying to open "
                << this->logFile << " log file for writing." << endl;
        abort();
    }
}

void CInternalLog::write(const short severity, const char *message, ...) {
    va_list arglist;
    time_t now;
    struct tm *currentTime;

    va_start(arglist, message);
    vsnprintf(this->lineBufferAux, MAXLOGLINE, message, arglist);
    va_end(arglist);

    if (severity * INT_LOG_MASK & this->internalLogOutputMask) {
        // This messages will be written to Internal Log.

        time(&now);
        currentTime = localtime(&now);
        snprintf(lineBuffer, MAXLOGLINE, "%04i-%02i-%02i %02i:%02i:%02i%c%s%c%s%c"
                , currentTime->tm_year + 1900
                , currentTime->tm_mon + 1
                , currentTime->tm_mday
                , currentTime->tm_hour
                , currentTime->tm_min
                , currentTime->tm_sec
                , this->fieldSeparator
                , this->severityArray[severity - 1]
                , this->fieldSeparator
                , this->lineBufferAux
                , this->endLine);

        this->logStream.write(this->lineBuffer, strlen(this->lineBuffer));
        if (this->logFastDump)
            this->logStream.flush();
    }

    if (severity * SYS_LOG_MASK & this->internalLogOutputMask) {
        // This messages will be written to system Log.
        int syslogSeverity;
        switch (severity) {
            case INFO_MESSAGE:
                syslogSeverity = LOG_INFO;
                break;
            case WARNING_MESSAGE:
                syslogSeverity = LOG_WARNING;
                break;
            case ERROR_MESSAGE:
                syslogSeverity = LOG_ERR;
                break;
        }
        syslog(syslogSeverity, "%s", this->lineBufferAux);
    }

    if (severity * STD_LOG_MASK & this->internalLogOutputMask) {
        // This messages will be written to Standar error output.
        cout << lineBufferAux << endl;
    }

}

bool CTrafficLog::initialize(CConfigurationManager &config) {
    this->logFile = config.trafficLogDir + "traffic.log";
    this->fastDump = config.logFastDump;
    this->fieldSeparator = config.logFieldSeparator.c_str()[0];
    this->endLine = config.logEnding.c_str()[0];
    this->logStream.open(this->logFile.c_str(), ios::out | ios::app | ios::binary);
    if (!this->logStream.is_open()) {
        cerr << "An error has occurred while trying to open "
                << this->logFile << " log file for writing." << endl;
        abort();
    }
}