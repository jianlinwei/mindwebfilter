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

#include "ConfigurationManager.hpp"
#include <cstdlib>
#include <string>
#include <string.h>
#include <iostream>
#include <libconfig.h++>


using namespace libconfig;
using namespace std;

static inline void criticalError(string filename, const char *key) {
    cerr << "Error reading global configuration file." << endl;
    cerr << "Missing " << key << " mandatory key." << endl
            << "Check " << filename << " file." << endl;
    exit(EXIT_FAILURE);
}

CConfigurationManager::CConfigurationManager() {
    this->reloadConfig = true;
    this->runForeground = false;
}

CConfigurationManager::~CConfigurationManager() {
}

bool CConfigurationManager::readConfiguration(string filename) {

    if (!this->reloadConfig)
        return false;
    else
        this->reloadConfig = false;

    try {
        this->cfg.readFile(filename.c_str());
    } catch (...) {
        cerr << "Error reading " << filename << " configuration file." << endl;
        exit(EXIT_FAILURE);
    }

    this->currentConfigFileName = filename;


    this->getConfigValue("configuration.config_file_version", this->configFileVersion, true);

    if (this->configFileVersion > MAX_CONFIG_FILE_VERSION) {
        cerr << "Warning: Confiuration file version for " << filename <<
                " is newer than supported." << endl
                << "Some keys may not be taken into account. "
                "Update MinD version in order to solve this issue." << endl;
    }

    this->getConfigValue("logs.internal_dir", this->internalLogDir, true);

    if (!this->getConfigValue("logs.fast_dump", this->logFastDump, false)) {
        this->logFastDump = false;
    }

    if (!this->getConfigValue("logs.traffic_dir", this->trafficLogDir, false)) {
        this->trafficLogDir = this->internalLogDir;
    }

    if (!this->getConfigValue("logs.memory_buffer_mb", this->logMemoryBufferMB, false)) {
        this->logMemoryBufferMB = 10;
    }

    if (this->logMemoryBufferMB < 0 || this->logMemoryBufferMB > 100) {
        cerr << "Warning: memory_buffer_mb confiuration key out of range."
                << endl << "It will be configured to default value." << endl;
        this->logMemoryBufferMB = 10;
    }

    if (!this->getConfigValue("logs.internal_output_mask", this->internalLogOutputMask, false)) {
        this->internalLogOutputMask = 511;
    }

    if (!this->getConfigValue("logs.field_separator", this->logFieldSeparator, false)) {
        this->logFieldSeparator = "\t";
    }

    if (!this->getConfigValue("logs.end_line", this->logEnding, false)) {
        this->logEnding = "\r";
    }

    this->getConfigValue("application.pid_file", this->pidFile, true);
    this->getConfigValue("application.run_user", this->runUser, true);
    this->getConfigValue("application.run_group", this->runGroup, true);
    if (!this->runForeground) // if this is true it is because it was setted by cmd line.
        this->getConfigValue("application.run_foreground", this->runForeground, false);

    this->getConfigValue("server.network.listen.address", this->serverNetworkListenAddress, true);
    this->getConfigValue("server.network.listen.port", this->serverNetworkListenPort, true);
    this->getConfigValue("server.engine.max_threads", this->serverEngineMaxThreads, true);
    if (!this->getConfigValue("server.engine.cpu.scheduling", this->serverEngineCPUscheduling, false))
        this->serverEngineCPUscheduling = 20;

    static int cpuQuantity;
    cpuQuantity = 0;
    for (int i = 0; i < 31; i++) {
        static char cpuNID[] = "server.engine.cpu.binding.cpuxx";
        static int idPos = strlen(cpuNID) - 2;
        sprintf(cpuNID + idPos, "%d\0", i);
        if (this->getConfigValue(cpuNID, this->serverEngineCPUbinding[i], false))
            if (this->serverEngineCPUbinding[i])
                cpuQuantity++;
    }

    if (cpuQuantity != this->serverEngineMaxThreads) {
        cout << "Warning, server.engine.max_threads is configured to "
                << this->serverEngineMaxThreads << endl;
        cout << "but there are " << cpuQuantity << " configured CPU." << endl;
        cout << "We recomend to fix your configuration in order "
                "to improve MinD Performance" << endl;
    }

    this->getConfigValue("server.engine.request_queue_size", this->serverEngineRequestQueueSize, true);

}

bool CConfigurationManager::getConfigValue(const char* keyName, long & destKey, bool mandatory) {
    try {
        Setting &s = this->cfg.lookup(keyName);
        destKey = s;
    } catch (...) {
        if (mandatory)
            criticalError(this->currentConfigFileName, keyName);
        else
            return false;
    }
    return true;
}

bool CConfigurationManager::getConfigValue(const char* keyName, std::string & destKey, bool mandatory) {
    try {
        string s = this->cfg.lookup(keyName);
        destKey = s;
    } catch (...) {
        if (mandatory)
            criticalError(this->currentConfigFileName, keyName);
        else
            return false;
    }
    return true;
}

bool CConfigurationManager::getConfigValue(const char* keyName, bool & destKey, bool mandatory) {
    try {
        bool s = this->cfg.lookup(keyName);
        destKey = s;
    } catch (...) {
        if (mandatory)
            criticalError(this->currentConfigFileName, keyName);
        else
            return false;
    }
    return true;
}