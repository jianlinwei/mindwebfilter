// Implements CSPlugin class and cs_plugin_loader base class

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.

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
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

#ifdef HAVE_CONFIG_H
#include "../mind_config.h"
#endif
#include "ContentScanner.hpp"
#include "ConfigVar.hpp"
#include "OptionContainer.hpp"
#include "Logger.hpp"


// GLOBALS
extern OptionContainer o;
extern Logger log;

// find the class factory functions for the CS plugins we've been configured to build

#ifdef ENABLE_CLAMD
extern cscreate_t clamdcreate;
#endif

#ifdef HAVE_CLAMAV
extern cscreate_t clamavcreate;
#endif

#ifdef ENABLE_ICAP
extern cscreate_t icapcreate;
#endif

#ifdef HAVE_KAVCLIENT
extern cscreate_t kavavcreate;
#endif

#ifdef ENABLE_KAVD
extern cscreate_t kavdcreate;
#endif

#ifdef ENABLE_COMMANDLINE
extern cscreate_t commandlinecreate;
#endif

// IMPLEMENTATION

// CSPlugin class

CSPlugin::CSPlugin(ConfigVar & definition) {
    cv = definition;
}

// start the plugin - i.e. read in the configuration

int CSPlugin::init(void* args) {
    if (!readStandardLists()) { //always
        return MIND_CS_ERROR; //include
    } // these
    return MIND_CS_OK;
}

// make a temporary file for storing data which is to be scanned
// returns FD in int and saves filename to String pointer
// filename is not used as input

int CSPlugin::makeTempFile(String * filename) {
    int tempfilefd;
    String tempfilepath(o.download_dir.c_str());
    tempfilepath += "/tfXXXXXX";
    char *tempfilepatharray = new char[tempfilepath.length() + 1];
    strcpy(tempfilepatharray, tempfilepath.toCharArray());
    if ((tempfilefd = mkstemp(tempfilepatharray)) < 1) {
#ifdef MIND_DEBUG
        std::cerr << "error creating cs temp " << tempfilepath << ": " << strerror(errno) << std::endl;
#endif
        log.writeToLog(1, "%s", "Could not create cs temp file.");
        tempfilefd = -1;
    } else {
        (*filename) = tempfilepatharray;
    }
    delete[]tempfilepatharray;
    return tempfilefd;
}

// write a temporary file containing the memory buffer which is to be scanned
// if your CS plugin does not have the ability to scan memory directly (e.g. clamdscan), this gets used by the default scanMemory to turn it into a file

int CSPlugin::writeMemoryTempFile(const char *object, unsigned int objectsize, String * filename) {
    int tempfd = makeTempFile(filename); // String gets modified
    if (tempfd < 0) {
#ifdef MIND_DEBUG
        std::cerr << "Error creating temp file in writeMemoryTempFile." << std::endl;
#endif
        log.writeToLog(1, "%s", "Error creating temp file in writeMemoryTempFile.");
        return MIND_CS_ERROR;
    }
    errno = 0;
#ifdef MIND_DEBUG
    std::cout << "About to writeMemoryTempFile " << (*filename) << " size: " << objectsize << std::endl;
#endif

    while (true) {
        if (write(tempfd, object, objectsize) < 0) {
            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
        }
        break; // end the while
    }
    close(tempfd); // finished writing so close file
    return MIND_CS_OK; // all ok
}

// default implementation of scanMemory, which defers to scanFile.

int CSPlugin::scanMemory(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
        const char *ip, const char *object, unsigned int objectsize) {
    // there is no capability to scan memory with some AV as we pass it
    // a file name to scan.  So we save the memory to disk and pass that.
    // Then delete the temp file.
    String tempfilepath;
    if (writeMemoryTempFile(object, objectsize, &tempfilepath) != MIND_CS_OK) {
#ifdef MIND_DEBUG
        std::cerr << "Error creating/writing temp file for scanMemory." << std::endl;
#endif
        log.writeToLog(1, "%s", "Error creating/writing temp file for scanMemory.");
        return MIND_CS_SCANERROR;
    }
    int rc = scanFile(requestheader, docheader, user, filtergroup, ip, tempfilepath.toCharArray());
#ifndef MIND_DEBUG
    unlink(tempfilepath.toCharArray()); // delete temp file
#endif
    return rc;
}

// read in all the lists of various things we do not wish to scan

bool CSPlugin::readStandardLists() {
    exceptionvirusmimetypelist.reset(); // incase this is a reload
    exceptionvirusextensionlist.reset();
    exceptionvirussitelist.reset();
    exceptionvirusurllist.reset();
    if (!exceptionvirusmimetypelist.readItemList(cv["exceptionvirusmimetypelist"].toCharArray(), false, 0)) {

        log.writeToLog(1, "%s", "Error opening exceptionvirusmimetypelist");
        return false;
    }
    exceptionvirusmimetypelist.doSort(false);
    if (!exceptionvirusextensionlist.readItemList(cv["exceptionvirusextensionlist"].toCharArray(), false, 0)) {

        log.writeToLog(1, "%s", "Error opening exceptionvirusextensionlist");
        return false;
    }
    exceptionvirusextensionlist.doSort(false);
    if (!exceptionvirussitelist.readItemList(cv["exceptionvirussitelist"].toCharArray(), false, 0)) {

        log.writeToLog(1, "%s", "Error opening exceptionvirussitelist");
        return false;
    }
    exceptionvirussitelist.doSort(false);
    if (!exceptionvirusurllist.readItemList(cv["exceptionvirusurllist"].toCharArray(), true, 0)) {

        log.writeToLog(1, "%s", "Error opening exceptionvirusurllist");
        return false;
    }
    exceptionvirusurllist.doSort(true);
    return true;
}

// test whether or not a request should be scanned based on sent & received headers

int CSPlugin::scanTest(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup, const char *ip) {
    char *i;

    //exceptionvirusmimetypelist
    String mimetype(docheader->getContentType());
#ifdef MIND_DEBUG
    std::cout << "mimetype: " << mimetype << std::endl;
#endif
    i = exceptionvirusmimetypelist.findInList(mimetype.toCharArray());
    if (i != NULL) {
        return MIND_CS_NOSCAN; // match
    }

    String disposition(docheader->disposition());
#ifdef MIND_DEBUG
    std::cout << "disposition: " << disposition << std::endl;
#endif
    String url(requestheader->url());
    String urld(requestheader->decode(url));
    urld.removeWhiteSpace();
    urld.toLower();
    urld.removePTP();
    String domain, tempurl, foundurl, path, extension;
    unsigned int fl;
    if (urld.contains("/")) {
        domain = urld.before("/");
        path = "/" + urld.after("/");
        path.hexDecode();
        path.realPath();
    } else {
        domain = urld;
    }

    // don't scan our web server
    if (((o.fg[filtergroup]->reporting_level == 1) || (o.fg[filtergroup]->reporting_level == 2)) && domain.startsWith(o.fg[filtergroup]->access_denied_domain)) {
        return MIND_CS_NOSCAN;
    }

    //exceptionvirusextensionlist
    if (disposition.length() > 2) {
        extension = disposition;
        while (extension.contains(".")) {
            extension = extension.after(".");
        }
        extension = "." + extension;
    } else {
        if (!path.contains("?")) {
            extension = path;
        } else if (mimetype.contains("application/")) {
            extension = path;
            if (extension.contains("?")) {
                extension = extension.before("?");
            }
        }
    }
#ifdef MIND_DEBUG
    std::cout << "extension: " << extension << std::endl;
#endif
    if (extension.contains(".")) {
        i = exceptionvirusextensionlist.findEndsWith(extension.toCharArray());
        if (i != NULL) {
            return MIND_CS_NOSCAN; // match
        }
    }

    // exceptionvirussitelist
    tempurl = domain;
#ifdef MIND_DEBUG
    std::cout << "domain: " << domain << std::endl;
#endif
    while (tempurl.contains(".")) {
        i = exceptionvirussitelist.findInList(tempurl.toCharArray());
        if (i != NULL) {
            return MIND_CS_NOSCAN; // exact match
        }
        tempurl = tempurl.after("."); // check for being in higher level domains
    }
    if (tempurl.length() > 1) { // allows matching of .tld
        tempurl = "." + tempurl;
        i = exceptionvirussitelist.findInList(tempurl.toCharArray());
        if (i != NULL) {
            return MIND_CS_NOSCAN; // exact match
        }
    }

    // exceptionvirusurllist
    tempurl = domain + path;
    if (tempurl.endsWith("/")) {
        tempurl.chop(); // chop off trailing / if any
    }
    while (tempurl.before("/").contains(".")) {
        i = exceptionvirusurllist.findStartsWith(tempurl.toCharArray());
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
            if (tempurl.length() > fl) {
                unsigned char c = tempurl[fl];
                if (c == '/' || c == '?' || c == '&' || c == '=') {
                    return MIND_CS_NOSCAN; // matches /blah/ or /blah/foo but not /blahfoo
                }
            } else {
                return MIND_CS_NOSCAN; // exact match
            }
        }
        tempurl = tempurl.after("."); // check for being in higher level domains
    }

#ifdef MIND_DEBUG
    std::cout << "URL " << url << " is going to need AV scanning." << std::endl;
#endif

    return MIND_CS_NEEDSCAN;
}

// take in a configuration file, find the CSPlugin class associated with the plugname variable, and return an instance

CSPlugin* cs_plugin_load(const char *pluginConfigPath) {
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {

        log.writeToLog(1, "Unable to load plugin config %s", pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);
    if (plugname.length() < 1) {
        log.writeToLog(1, "Unable read plugin config plugname variable %s", pluginConfigPath);
        return NULL;
    }

#ifdef ENABLE_CLAMD
    if (plugname == "clamdscan") {
#ifdef MIND_DEBUG
        std::cout << "Enabling ClamDscan CS plugin" << std::endl;
#endif
        return clamdcreate(cv);
    }
#endif

#ifdef HAVE_CLAMAV
    if (plugname == "clamav") {
#ifdef MIND_DEBUG
        std::cout << "Enabling ClamAV CS plugin" << std::endl;
#endif
        return clamavcreate(cv);
    }
#endif

#ifdef HAVE_KAVCLIENT
    if (plugname == "kavav") {
#ifdef MIND_DEBUG
        std::cout << "Enabling KAVClient CS plugin" << std::endl;
#endif
        return kavavcreate(cv);
    }
#endif

#ifdef ENABLE_KAVD
    if (plugname == "kavdscan") {
#ifdef MIND_DEBUG
        std::cout << "Enabling KAVDscan CS plugin" << std::endl;
#endif
        return kavdcreate(cv);
    }
#endif

#ifdef ENABLE_ICAP
    if (plugname == "icapscan") {
#ifdef MIND_DEBUG
        std::cout << "Enabling ICAPscan CS plugin" << std::endl;
#endif
        return icapcreate(cv);
    }
#endif

#ifdef ENABLE_COMMANDLINE
    if (plugname == "commandlinescan") {
#ifdef MIND_DEBUG
        std::cout << "Enabling command-line CS plugin" << std::endl;
#endif
        return commandlinecreate(cv);
    }
#endif


    log.writeToLog(1, "Unable to load plugin %s\n", pluginConfigPath);
    return NULL;
}
