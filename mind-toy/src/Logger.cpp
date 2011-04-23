/*
 * File:   Logger.cpp
 *
 * Created on 9 de abril de 2010, 19:06
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "Logger.hpp"

#ifdef HAVE_CONFIG_H
#include "../mind_config.h"
#endif
#include "String.hpp"

Logger::Logger() {
    this->internalLogfilemask = 28; // Info+Warning+Error to stderr.
    this->fpInternalLog = NULL;
    this->internalLogFilename = NULL;
    this->fpRequestLog = NULL;
    this->requestLogFilename = NULL;
    this->accessLogFieldSeparator = NULL;
    this->accessLogFieldEndLine = NULL;
}

Logger::~Logger() {
    this->freeMemFiles();
}

void Logger::freeMemFiles() {
    if (this->fpInternalLog)
        fclose(fpInternalLog);
    if (this->internalLogFilename)
        free(this->internalLogFilename);
    if (this->fpRequestLog)
        fclose(fpRequestLog);
    if (this->requestLogFilename)
        free(this->requestLogFilename);
    if (this->fpstatLog)
        fclose(this->fpstatLog);
    if (this->statLogFilename)
        free(this->statLogFilename);
    if (this->accessLogFieldSeparator)
        free(this->accessLogFieldSeparator);
    if (this->accessLogFieldEndLine)
        free(this->accessLogFieldEndLine);
}

void Logger::setInternalLogMask(int logfilemask) {
    this->internalLogfilemask = logfilemask;
}

void Logger::setAccessLogFieldMask(int accessLogFieldMask) {
    this->accessLogFieldMask = accessLogFieldMask;
}

bool Logger::setLogLocation(const char* path) {
    return this->openLogFiles(path);
}

void Logger::setFlushLogsImmediately(bool flushLogsImmediately) {
    this->flushLogsImmediately = flushLogsImmediately;
}

bool Logger::getUserAgentLogValue() {
    return this->accessLogFieldMask & 32;
}

void Logger::setAccessLogFieldSeparator(const char * accessLogFieldSeparator) {
    if (this->accessLogFieldSeparator)
        free(this->accessLogFieldSeparator);
    this->accessLogFieldSeparator = strdup(accessLogFieldSeparator);
    replaceEscChars(this->accessLogFieldSeparator);
}

void Logger::setAccessLogFieldEndLine(const char * accessLogFieldEndLine) {
    if (this->accessLogFieldEndLine)
        free(this->accessLogFieldEndLine);
    this->accessLogFieldEndLine = strdup(accessLogFieldEndLine);
    replaceEscChars(this->accessLogFieldEndLine);
}

bool Logger::openLogFiles(const char *path) {
    char * mindLogFilename;
    char * reqLogFilename;
    char * statLogFilename;

    this->freeMemFiles();

    mindLogFilename = (char*) malloc((strlen(path) + 20) * sizeof (char));
    mindLogFilename[0] = '\0';
    strcat(mindLogFilename, path);
    strcat(mindLogFilename, "/");
    strcat(mindLogFilename, "mind.log"); // TODO: Modify the magic num ate malloc.

    reqLogFilename = (char*) malloc((strlen(path) + 20) * sizeof (char));
    reqLogFilename[0] = '\0';
    strcat(reqLogFilename, path);
    strcat(reqLogFilename, "/");
    strcat(reqLogFilename, "request.log"); // TODO: Modify the magic num ate malloc.

    statLogFilename = (char*) malloc((strlen(path) + 20) * sizeof (char));
    statLogFilename[0] = '\0';
    strcat(statLogFilename, path);
    strcat(statLogFilename, "/");
    strcat(statLogFilename, "stat.log"); // TODO: Modify the magic num ate malloc.

    this->fpInternalLog = fopen(mindLogFilename, "a+");
    this->internalLogFilename = mindLogFilename;

    this->fpRequestLog = fopen(reqLogFilename, "a+");
    this->requestLogFilename = reqLogFilename;

    this->fpstatLog = fopen(statLogFilename, "a+");
    this->statLogFilename = statLogFilename;

    if (this->fpInternalLog && this->fpRequestLog && this->fpstatLog)
        return true;

    else
        return false;
}

void Logger::writeToLog(const char *message, ...) {

    va_list arglist;
    va_start(arglist, message);
    this->writeToLog(0, message, arglist);
    va_end(arglist);
}

void Logger::writeToLog(const int code, const char *message, ...) {
    va_list arglist;
    va_start(arglist, message);

    if ((code == 0 && this->internalLogfilemask & 1) ||
            (code < 0 && this->internalLogfilemask & 2) ||
            (code > 0 && this->internalLogfilemask & 4))
        if (this->fpInternalLog) {
            time(&this->now);
            this->current_time = localtime(&this->now);
            fprintf(this->fpInternalLog, "%04i-%02i-%02i %02i:%02i:%02i\t",
                    this->current_time->tm_year + 1900,
                    this->current_time->tm_mon + 1,
                    this->current_time->tm_mday,
                    this->current_time->tm_hour,
                    this->current_time->tm_min,
                    this->current_time->tm_sec
                    );
            vfprintf(this->fpInternalLog, message, arglist);
            fprintf(this->fpInternalLog, "\n");
        }
    if ((code == 0 && this->internalLogfilemask & 8) ||
            (code < 0 && this->internalLogfilemask & 16) ||
            (code > 0 && this->internalLogfilemask & 32)) {
        if (code == 0) {
            syslog(LOG_INFO, message, arglist);
        } else if (code < 0) {
            syslog(LOG_WARNING, message, arglist);
        } else if (code > 0)
            syslog(LOG_ERR, message, arglist);
    }

    if ((code == 0 && this->internalLogfilemask & 64) ||
            (code < 0 && this->internalLogfilemask & 128) ||
            (code > 0 && this->internalLogfilemask & 256)) {

        vfprintf(stderr, message, arglist);
        fprintf(stderr, "\n");
    }

    va_end(arglist);
}

char* Logger::getInternalLogFilename() {

    return this->internalLogFilename;
}

char* Logger::getRequestLogFilename() {

    return this->requestLogFilename;
}

char* Logger::getStatLogFilename() {

    return this->statLogFilename;
}

/* Logger::testLogs(const char code)
 * code=
 *       I = Internal.
 *       R = Request.
 *       S = Statistics.
 */
bool Logger::testLogs(const char code) {
    bool ret;
    ret = false;
    switch (code) {
        case 'I':
            if (this->internalLogFilename && this->fpInternalLog)
                ret = true;
            break;
        case 'R':
            if (this->requestLogFilename && this->fpRequestLog)
                ret = true;
            break;
        case 'S':
            if (this->statLogFilename && this->fpstatLog)
                ret = true;

            break;
    }
    return ret;
}

bool Logger::testLogs() {

    return (testLogs('I') && testLogs('R') && testLogs('S'));
}

void Logger::writeToAccessLog(const char* message) {

    if (this->fpRequestLog) {

        fputs(message, this->fpRequestLog);
        fputc('\n', this->fpRequestLog);
        fflush(this->fpRequestLog);
    }
}

void Logger::writeToAccessLog(const char *separator, const char* field, ...) {

    if (this->fpRequestLog) {
        va_list arglist;
        va_start(arglist, field);
        vfprintf(this->fpRequestLog, field, arglist);
        va_end(arglist);

        if (separator) {

            fprintf(this->fpRequestLog, "%s", separator);
        }
    }
}

void Logger::writeToAccessLog(stRequestLog *requestLog) {

    if (requestLog->destinationPort && requestLog->destinationPort != 80) {
        // put port numbers of non-standard HTTP requests into the logged URL

        String tempDestURL(requestLog->destinationURL);
        if (tempDestURL.after("://").contains("/")) {
            String proto, host, path;
            proto = tempDestURL.before("://");
            host = tempDestURL.after("://");
            path = host.after("/");
            host = host.before("/");
            tempDestURL = proto;
            tempDestURL += "://";
            tempDestURL += host;
            tempDestURL += ":";
            tempDestURL += String((int) requestLog->destinationPort);
            tempDestURL += "/";
            tempDestURL += path;
        } else {
            tempDestURL += ":";
            tempDestURL += String((int) requestLog->destinationPort);
        }

        if (requestLog->destinationURL)
            free(requestLog->destinationURL);
        requestLog->destinationURL = strdup(tempDestURL.c_str());
    }

    time(&this->now);
    this->current_time = localtime(&this->now);

    if (this->accessLogFieldMask & 1)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%04i-%02i-%02i %02i:%02i:%02i",
            this->current_time->tm_year + 1900,
            this->current_time->tm_mon + 1,
            this->current_time->tm_mday,
            this->current_time->tm_hour,
            this->current_time->tm_min,
            this->current_time->tm_sec
            );

    if (this->accessLogFieldMask & 2)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->userIPAddress);

    if (this->accessLogFieldMask & 4)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->userName);

    if (this->accessLogFieldMask & 8)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->profileName ? requestLog->profileName : "-");

    if (this->accessLogFieldMask & 16)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->clientHost);

    if (this->accessLogFieldMask & 32)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->userAgent);

    if (this->accessLogFieldMask & 64)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->destinationURL);

    if (this->accessLogFieldMask & 128)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%d", requestLog->destinationPort);

    if (this->accessLogFieldMask & 256)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->httpMethod);

    if (this->accessLogFieldMask & 512)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%d", requestLog->objectSize);

    if (this->accessLogFieldMask & 1024)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%d", requestLog->objectStatusCode);

    if (this->accessLogFieldMask & 2048)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->objectMimeType);

    if (this->accessLogFieldMask & 4096) {
        if (requestLog->blockeableContent) {
            writeToAccessLog(this->accessLogFieldSeparator, "Blocked");
        } else if (requestLog->isAnException) {
            writeToAccessLog(this->accessLogFieldSeparator, "Exception");
        }
        if (requestLog->wasScanned) {
            if (requestLog->isInfected) {
                writeToAccessLog(this->accessLogFieldSeparator, "Infected");
            } else {
                writeToAccessLog(this->accessLogFieldSeparator, "Analysed");
            }
        }
        if (requestLog->contentModified) {
            writeToAccessLog(this->accessLogFieldSeparator, "Content_Mod");
        }
        if (requestLog->urlModified) {
            writeToAccessLog(this->accessLogFieldSeparator, "URL_Mod");
        }
        if (requestLog->headerModified) {
            writeToAccessLog(this->accessLogFieldSeparator, "Header_Mod");
        }
    }

    if (this->accessLogFieldMask & 8192)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->actionReason ? requestLog->actionReason : "-");

    if (this->accessLogFieldMask & 16384)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%d", requestLog->objectWeight);

    if (this->accessLogFieldMask & 32768)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->objectCategory);

    if (this->accessLogFieldMask & 65536)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->isAnException ? "1" : "0");

    if (this->accessLogFieldMask & 131072)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->wasScanned ? "1" : "0");

    if (this->accessLogFieldMask & 262144)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->isInfected ? "1" : "0");

    if (this->accessLogFieldMask & 524288)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->contentModified ? "1" : "0");

    if (this->accessLogFieldMask & 1048576)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->urlModified ? "1" : "0");

    if (this->accessLogFieldMask & 2097152)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->urlModified ? "1" : "0");

    if (this->accessLogFieldMask & 4194304)
        writeToAccessLog(this->accessLogFieldSeparator,
            "%s", requestLog->blockeableContent ? "1" : "0");

    writeToAccessLog(NULL, "%s", this->accessLogFieldEndLine);

    if (this->flushLogsImmediately)
        fflush(this->fpRequestLog);
}

void Logger::stAccessLogDrop(stRequestLog *requestLog) {
    if (!requestLog) return;
    if (requestLog->actionReason)
        free(requestLog->actionReason);
    if (requestLog->clientHost)
        free(requestLog->clientHost);
    if (requestLog->destinationURL)
        free(requestLog->destinationURL);
    if (requestLog->httpMethod)
        free(requestLog->httpMethod);
    if (requestLog->objectCategory)
        free(requestLog->objectCategory);
    if (requestLog->objectMimeType)
        free(requestLog->objectMimeType);
    if (requestLog->profileName)
        free(requestLog->profileName);
    if (requestLog->userAgent)
        free(requestLog->userAgent);

    if (requestLog->userName)
        free(requestLog->userName);
    free(requestLog);
}

bool Logger::stAccessLogResrv(stRequestLog **requestLog) {
    *requestLog = (stRequestLog*) malloc(sizeof (stRequestLog));
    memset(*requestLog, '\0', sizeof (stRequestLog));
}

void replaceEscChars(char* string) {
    int i = 0;
    int j = 0;
    int lenght = strlen(string);
    char c;
    while (i <= lenght) {
        c = string[i++];
        if (c == '\\' && i <= lenght) {
            switch ((c = string[i++])) {
                case 't':
                    string[j++] = '\t';
                    break;
                case 'n':
                    string[j++] = '\n';
                    break;
                case '\\':
                    string[j++] = '\\';
                    break;
                case '0':
                    string[j++] = '\0';
                    break;
                default:
                    string[j++] = '\\';
                    break;
            }
        } else
            string[j++] = c;
    }
}