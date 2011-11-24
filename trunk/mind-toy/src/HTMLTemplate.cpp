//Implements the HTMLTemplate class, for displaying template-based banned pages to clients

//Written by Daniel Barron (daniel@//jadeb.com).
//Modified by MinD Team on 2011.

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
#include "HTMLTemplate.hpp"
#include "RegExp.hpp"
#include "String.hpp"
#include "OptionContainer.hpp"
#include "Logger.hpp"

#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <syslog.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>


// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;
extern Logger log;

// IMPLEMENTATION

HTMLTemplate::HTMLTemplate() {
    switch (o.blocking_page_ph_style) {
        case 0:
            placeHolderList[0] = "-URL-";
            placeHolderList[1] = "-REASONGIVEN-";
            placeHolderList[2] = "-REASONLOGGED-";
            placeHolderList[3] = "-USER-";
            placeHolderList[4] = "-IP-";
            placeHolderList[5] = "-HOST-";
            placeHolderList[6] = "-FILTERGROUP-";
            placeHolderList[7] = "-RAWFILTERGROUP-";
            placeHolderList[8] = "-BYPASS-";
            placeHolderList[9] = "-CATEGORIES-";
            placeHolderList[10] = "-SERVERIP-";
            placeHolderList[11] = "-WEBSERVERIP-";
            break;
        case 1:
            placeHolderList[0] = "<!--URL-->";
            placeHolderList[1] = "<!--REASONGIVEN-->";
            placeHolderList[2] = "<!--REASONLOGGED-->";
            placeHolderList[3] = "<!--USER-->";
            placeHolderList[4] = "<!--IP-->";
            placeHolderList[5] = "<!--HOST-->";
            placeHolderList[6] = "<!--FILTERGROUP-->";
            placeHolderList[7] = "<!--RAWFILTERGROUP-->";
            placeHolderList[8] = "<!--BYPASS-->";
            placeHolderList[9] = "<!--CATEGORIES-->";
            placeHolderList[10] = "<!--SERVERIP-->";
            placeHolderList[11] = "<!--WEBSERVERIP-->";
            break;
        default:
            placeHolderList[0] = "mind.siteURL()";
            placeHolderList[1] = "mind.reasonGiven()";
            placeHolderList[2] = "mind.reasonLogged()";
            placeHolderList[3] = "mind.user()";
            placeHolderList[4] = "mind.clientIP()";
            placeHolderList[5] = "mind.clientHostName()";
            placeHolderList[6] = "mind.filterProfile()";
            placeHolderList[7] = "mind.rawfilterProfile()";
            placeHolderList[8] = "mind.bypass()";
            placeHolderList[9] = "mind.categories()";
            placeHolderList[10] = "mind.serverIP()";
            placeHolderList[11] = "mind.webServerIP()";
            break;
    }
    placeHoldersMap = NULL;
}

HTMLTemplate::~HTMLTemplate() {
    placeholdersList *placeHoldersMap_aux;
    if (placeHoldersMap) {
        do {
            placeHoldersMap_aux = placeHoldersMap->next;
            free(placeHoldersMap);
        } while (placeHoldersMap = placeHoldersMap_aux);
    }
}

// wipe the loaded template

void HTMLTemplate::reset() {
    html.clear();
}

// push a line onto our string list

void HTMLTemplate::push(String s) {
    if (s.length() > 0) {
        html.push_back(s);
    }
}

void HTMLTemplate::placeholdersListAdd(int line, int column, int id, int size) {
    placeHoldersMapAux = (struct placeholdersList*) malloc(sizeof (struct placeholdersList));
    placeHoldersMapAux->column = column;
    placeHoldersMapAux->id = id;
    placeHoldersMapAux->line = line;
    placeHoldersMapAux->size = size;
    placeHoldersMapAux->previous = placeHoldersMap;
    placeHoldersMapAux->next = NULL;
    if (placeHoldersMap)
        placeHoldersMap->next = placeHoldersMapAux;
    placeHoldersMap = placeHoldersMapAux;
}

void HTMLTemplate::locatePlaceholders(char* lineBuffer, int lineNumber) {
    int id;
    int size;
    char* position;

    for (id = 0; id <= 11; id++) {
        if (position = strstr(lineBuffer, placeHolderList[id])) {
            size = strlen(placeHolderList[id]);
            break;
        }
    }

    if (id <= 11) {
        placeholdersListAdd(lineNumber, position - lineBuffer, id, size);
        locatePlaceholders(position + size, lineNumber);
    }
}

bool HTMLTemplate::readTemplateFile(const char *filename) {
    FILE *fp;
    char lineBuffer[512];
    char* longLineBuffer;
    int lineNumber;

    if (!(fp = fopen(filename, "r"))) {
        log.writeToLog(1, "Error reading HTML Template file: %s", filename);
        return false;
    }
    lineNumber = 0;
    while (!feof(fp)) {
        fgets(lineBuffer, 512, fp);
        push(lineBuffer);
        if (lineBuffer[strlen(lineBuffer) - 1] == '\n') {
            locatePlaceholders(lineBuffer, lineNumber++);
        } else {
            longLineBuffer = strdup(lineBuffer);
            do {
                fgets(lineBuffer, 512, fp);
                longLineBuffer = (char*) realloc(longLineBuffer, strlen(longLineBuffer) + strlen(lineBuffer) + 1);
                strcat(longLineBuffer, lineBuffer);
            } while (lineBuffer[strlen(lineBuffer) - 1] != '\n' && !feof(fp));
            locatePlaceholders(longLineBuffer, ++lineNumber);
            free(longLineBuffer);
        }
    }
    fclose(fp);

    if (placeHoldersMap) {
        while (placeHoldersMap->previous)
            placeHoldersMap = placeHoldersMap->previous;
    }

    return true;
}

// fill in placeholders with the given information and send the resulting page to the client
// only useful if you used the default set of placeholders

void HTMLTemplate::display(Socket *s, String *url, std::string &reason, std::string &logreason, std::string &categories,
        std::string *user, std::string *ip, std::string *host, int filtergroup, String & hashed) {

    if (reason == "Banned site: googlesyndication.com" || reason == "Banned site: googleadservices.com")
    {
        std::string redirection;
        std::size_t url_pos;
        redirection="<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>Moved</TITLE><meta http-equiv=\"refresh\" content=\"0;url=";
        url_pos = url->rfind("adurl=");
        if (url_pos!=std::string::npos) {
          url_pos += 6;
          redirection.append(url->substr(url_pos, url->length() - url_pos));
          redirection.append("\"></HEAD></HTML>\n");
          (*s).writeString(redirection.c_str());
          return;
       }
    }

#ifdef MIND_DEBUG
    std::cout << "Displaying TEMPLATE" << std::endl;
#endif

    unsigned int line;
    unsigned int lastline;
    bool urlIsSafe;

    placeHoldersMapAux = placeHoldersMap;
    line = 0;
    lastline = html.size();
    urlIsSafe = false;

    while (placeHoldersMapAux) {
        if (line == placeHoldersMapAux->line) {
            (*s).writeString(html[line].subString(0, placeHoldersMapAux->column).toCharArray());
            switch (placeHoldersMapAux->id) {
                case 0: // URL
                    if (!urlIsSafe) {
                        url->replaceall("'", "%27");
                        url->replaceall("\"", "%22");
                        url->replaceall("<", "%3C");
                        url->replaceall(">", "%3E");
                        urlIsSafe = true;
                    }
                    (*s).writeString(url->c_str());
                    break;
                case 1: // REASONGIVEN
                    (*s).writeString(reason.c_str());
                    break;
                case 2: // REASONLOGGED
                    (*s).writeString(logreason.c_str());
                    break;
                case 3: // USER
                    (*s).writeString(user->c_str());
                    break;
                case 4: // IP
                    (*s).writeString(ip->c_str());
                    break;
                case 5: // HOST
                    if (host == NULL) {
#ifdef MIND_DEBUG
                        std::cout << "-HOST- placeholder encountered but hostname currently unknown; lookup forced." << std::endl;
#endif
                        std::deque<String> *names = ipToHostname(ip->c_str());
                        if (names->size() > 0)
                            (*s).writeString(names->front().toCharArray());
                        delete names;
                    } else
                        (*s).writeString(host->c_str());
                    break;
                case 6: // FILTERGROUP
                    (*s).writeString(o.fg[filtergroup]->name.c_str());
                    break;
                case 7: // RAWFILTERGROUP
                    (*s).writeString(String(filtergroup + 1).c_str());
                    break;
                case 8: // BYPASS
                    if (hashed.length() > 0) {
                        (*s).writeString(url->c_str());
                        if (!(url->after("://").contains("/"))) {
                            (*s).writeString("/");
                        }
                        if (url->contains("?")) {
                            (*s).writeString("&");
                        } else {
                            (*s).writeString("?");
                        }
                        (*s).writeString(hashed.c_str());
                    }
                    break;
                case 9: // CATEGORIES
                    if (categories.length() > 0) {
                        (*s).writeString(categories.c_str());
                    } else {
                        (*s).writeString("N/A");
                    }
                    break;
                case 10: // SERVERIP
                    (*s).writeString(String(s->getLocalIP()).c_str());
                    break;
                case 11: // WEBSERVERIP
                    (*s).writeString(o.web_server);
                    break;
            }

            if (placeHoldersMapAux->next && placeHoldersMapAux->next->line != line || !placeHoldersMapAux->next)
                (*s).writeString(html[line].subString(placeHoldersMapAux->column + placeHoldersMapAux->size,
                    html[line].length() - (placeHoldersMapAux->column + placeHoldersMapAux->size)).toCharArray());

            if (!placeHoldersMapAux->next)
            {
                line++;
                break;
            }

            placeHoldersMapAux = placeHoldersMapAux->next;

        } else
            (*s).writeString(html[line].toCharArray());

        if (line != placeHoldersMapAux->line)
            line++;
        
        usleep(600);
    }

    for (; line < lastline-1; line++) {
        (*s).writeString(html[line].toCharArray());
        usleep(500);
    }
}
