/* 
 * File:   Logger.hpp
 *
 * Created on 9 de abril de 2010, 19:06
 *
 */

#ifndef _LOGGER_HPP
#define	_LOGGER_HPP

#include <string>

struct stRequestLog {
    char* userName;
    char userIPAddress[16];
    char* destinationURL;
    bool isAnException;
    bool wasScanned;
    bool isInfected;
    bool contentModified;
    bool urlModified;
    bool headerModified;
    bool blockeableContent;
    char* actionReason;
    char* httpMethod;
    int objectSize;
    int objectWeight;
    char* objectCategory;
    int filtergroup;
    char* filtergroupName;
    int destinationPort;
    int objectStatusCode;
    char* objectMimeType;
    char* clientHost;
    char* profileName;
    char* userAgent;
    bool cacheHit;
};

void replaceEscChars(char* string);

class Logger {
public:
    void setInternalLogMask(int logfilemask);
    bool setLogLocation(const char *path);
    void setAccessLogFieldSeparator(const char * accessLogFieldSeparator);
    void setAccessLogFieldEndLine(const char * accessLogFieldEndLine);
    void setAccessLogFieldMask(int accessLogFieldMask);
    void setFlushLogsImmediately(bool flushLogsImmediately);
    bool getUserAgentLogValue();
    void writeToLog(const char *message, ...);
    void writeToLog(const int code, const char *message, ...);
    void writeToAccessLog(const char *message);
    void writeToAccessLog(stRequestLog *requestLog);
    void writeToAccessLog(const char *separator, const char* field, ...);
    bool stAccessLogResrv(stRequestLog **requestLog);
    void stAccessLogDrop(stRequestLog *requestLog);
    char* getInternalLogFilename();
    char* getRequestLogFilename();
    char* getStatLogFilename();
    bool testLogs(const char code);
    bool testLogs();
    Logger();
    ~Logger();
private:
    bool openLogFiles(const char *path);
    void freeMemFiles();
    char *accessLogFieldSeparator;
    char *accessLogFieldEndLine;
    bool flushLogsImmediately;
    int internalLogfilemask;
    int accessLogFieldMask;
    char *internalLogFilename;
    FILE *fpInternalLog;
    char *requestLogFilename;
    FILE *fpRequestLog;
    char *statLogFilename;
    FILE *fpstatLog;
    struct tm *current_time;
    time_t now;
};


#endif	/* _LOGGER_HPP */

