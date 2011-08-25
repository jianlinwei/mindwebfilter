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

#ifndef LOGMANAGER_HPP
#define	LOGMANAGER_HPP
#include <stdlib.h>
#include <iostream>
#include <fstream>

#include "ConfigurationManager.hpp"

using namespace std;

#define INFO_MESSAGE        1
#define WARNING_MESSAGE     2
#define ERROR_MESSAGE       4
#define INT_LOG_MASK        1
#define SYS_LOG_MASK        8
#define STD_LOG_MASK        64
#define MAXLOGLINE        4096

class CLogManager {
public:
    CLogManager();
    ~CLogManager();

protected:
    string logFile;
    char fieldSeparator;
    char endLine;
    ofstream logStream;
    bool logFastDump;
};

#endif	/* LOGMANAGER_HPP */

class CInternalLog : public CLogManager {
public:
    CInternalLog();
    ~CInternalLog();
    bool initialize(CConfigurationManager &config);
    void write(const short severity, const char *message, ...);
private:
    long internalLogOutputMask;
    char lineBuffer[MAXLOGLINE];
    char lineBufferAux[MAXLOGLINE];
    char severityArray[4][8];
};

class CTrafficLog : public CLogManager {
public:
    CTrafficLog();
    ~CTrafficLog();
    bool initialize(CConfigurationManager &config);
    void write(const char *message, ...);
private:
    long memoryBuffer;
    bool fastDump;
    char* memoryBufferBlock;
    long internalLogOutputMask;
};

