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

#ifndef CONFIGURATIONMANAGER_HPP
#define	CONFIGURATIONMANAGER_HPP

#define MAX_CONFIG_FILE_VERSION     1

#include <string>
#include <libconfig.h++>

class CConfigurationManager {
public:
    CConfigurationManager();
    ~CConfigurationManager();

    bool readConfiguration(std::string filename);

    // All MinD configuration keys.
    long configFileVersion;
    std::string internalLogDir;
    std::string trafficLogDir;
    bool logFastDump;
    long logMemoryBufferMB;
    long internalLogOutputMask;
    std::string logFieldSeparator;
    std::string logEnding;
    std::string pidFile;
    pid_t pid;
    std::string runUser;
    std::string runGroup;
    int rootUID;
    bool runForeground;
    bool reloadConfig;
    std::string serverNetworkListenAddress;
    long serverNetworkListenPort;
    long serverEngineMaxThreads;
    long serverEngineCPUscheduling;
    bool serverEngineCPUbinding[32];
    long serverEngineRequestQueueSize;

private:
    libconfig::Config cfg;
    std::string currentConfigFileName;
    bool getConfigValue(const char* keyName, long & destKey, bool mandatory);
    bool getConfigValue(const char* keyName, std::string & destKey, bool mandatory);
    bool getConfigValue(const char* keyName, bool & destKey, bool mandatory);
};

#endif	/* CONFIGURATIONMANAGER_HPP */

