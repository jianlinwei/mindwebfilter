//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb.com).
//For support go to http://groups.yahoo.com/group/dansguardian

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

//This file contains modifications suggested and mostly provided by
//Daniel Robbins 13/4/01 drobbins@gento.org
//Modifications include, but not limited to, getcontenttype(), << , >>


// INCLUDES

#ifdef HAVE_CONFIG_H
#include "../mind_config.h"
#endif
#include "HTTPHeader.hpp"
#include "Socket.hpp"
#include "OptionContainer.hpp"
#include "FDTunnel.hpp"
#include "Logger.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <exception>
#include <time.h>

#include <cerrno>
#include <zlib.h>

// GLOBALS
extern OptionContainer o;

// regexp for decoding %xx in URLs
extern RegExp urldecode_re;


// IMPLEMENTATION

// set timeout for socket operations

void HTTPHeader::setTimeout(int t) {
    timeout = t;
}

// reset header object for future use

void HTTPHeader::reset() {
    if (dirty) {
        header.clear();
        //postdata.reset();
        postdata[0] = '\0';
        postdatalen = 0;
        postdatachopped = false;
        ispostupload = false;
        waspersistent = false;
        ispersistent = false;

        cachedurl = "";

        phost = NULL;
        pport = NULL;
        pcontentlength = NULL;
        pcontenttype = NULL;
        pproxyauthorization = NULL;
        pcontentdisposition = NULL;
        puseragent = NULL;
        pxforwardedfor = NULL;
        pcontentencoding = NULL;
        pproxyconnection = NULL;

        dirty = false;
    }
}

// *
// *
// * header value and type checks
// *
// *

String HTTPHeader::requestType() {
    return header.front().before(" ");
}

// grab return code

int HTTPHeader::returnCode() {
    return header.front().after(" ").before(" ").toInteger();
}

// grab content length

off_t HTTPHeader::contentLength() {
    // code 304 - not modified - no content
    String temp(header.front().after(" "));
    if (temp.startsWith("304"))
        return 0;
    if (pcontentlength != NULL) {
        temp = pcontentlength->after(" ");
        return temp.toOffset();
    }
    // no content-length header - we don't know
    return -1;
}

// grab the auth type

String HTTPHeader::getAuthType() {
    if (pproxyauthorization != NULL) {
        return pproxyauthorization->after(" ").before(" ");
    }
    return "";
}

// check the request's return code to see if it's an auth required message

bool HTTPHeader::authRequired() {
    String temp(header.front().after(" "));
    if (temp.startsWith("407")) {
        return true;
    }
    return false;
}

// grab content disposition

String HTTPHeader::disposition() {
    if (pcontentdisposition != NULL) {
        String filename(pcontentdisposition->after("filename").after("="));
        if (filename.contains(";"))
            filename = filename.before(";");
        filename.removeWhiteSpace(); // incase of trailing space
        if (filename.contains("\"")) {
            return filename.after("\"").before("\"");
        }
        return filename;
        // example format:
        // Content-Disposition: attachment; filename="filename.ext"
        // Content-Disposition: attachment; filename=filename.ext
        // Content-Disposition: filename="filename.ext"
        // 3rd format encountered from download script on realVNC's
        // website. notice it does not contain any semicolons! PRA 4-11-2005
    }
    return ""; // it finds the header proposed filename
}

// grab the user agent

String HTTPHeader::userAgent() {
    if (puseragent != NULL) {
        // chop off '/r'
        String result(puseragent->after(" "));
        result.resize(result.length() - 1);
        return result;
    }
    return "";
}

// grab the content type header

String HTTPHeader::getContentType() {
    if (pcontenttype != NULL) {
        String mimetype(pcontenttype->after(" "));
        if (mimetype.length() < 1)
            return "-";

        unsigned char c;
        size_t j = 0;
        while (j < mimetype.length()) {
            c = mimetype[j];
            if (c == ' ' || c == ';' || c < 32) { // remove the
                mimetype = mimetype.subString(0, j);
                // extra info not needed
                j = 0;
            }
            ++j;
        }

        mimetype.toLower();
        return mimetype;
    }
    return "-";
}

// does the given content type string match our headers?

bool HTTPHeader::isContentType(const String& t) {
    return getContentType().startsWith(t);
}

// grab contents of X-Forwarded-For header
// Modification based on a submitted patch by
// Jimmy Myrick (jmyrick@tiger1.tiger.org)

std::string HTTPHeader::getXForwardedForIP() {
    if (pxforwardedfor != NULL) {
        String line(pxforwardedfor->after(": "));
        line.chop();
        return std::string(line.toCharArray());
    }
    return "";
}

// check the return code to see if it's a redirection request

bool HTTPHeader::isRedirection() {
    // The 1st line of the header for a redirection is thus:
    // HTTP/1.(0|1) 3xx
    if (header.size() < 1) {
        return false;
    } // sometimes get called b 4 read
    String answer(header.front().after(" ").before(" "));
    if (answer[0] == '3' && answer.length() == 3) {
        return true;
    }
    return false;
}

// grab the contents of Proxy-Authorization header
// returns base64-decoding of the chunk of data after the auth type string

std::string HTTPHeader::getAuthData() {
    if (pproxyauthorization != NULL) {
        String line(pproxyauthorization->after(" ").after(" "));
        return decodeb64(line); // it's base64 MIME encoded
    }
    return "";
}

// grab raw contents of Proxy-Authorization header without decoding

std::string HTTPHeader::getRawAuthData() {
    if (pproxyauthorization != NULL) {
        return pproxyauthorization->after(" ").after(" ");
    }
    return "";
}

// do we have a non-identity content encoding? this means body is compressed

bool HTTPHeader::isCompressed() {
    if (pcontentencoding != NULL) {
        if (pcontentencoding->indexOf("identity") != -1) {
            // http1.1 says this
            // should not be here, but not must not
            return false;
        }
#ifdef MIND_DEBUG
        std::cout << "is compressed" << std::endl;
#endif
        return true; // i.e. encoded with something other than clear
    }
    return false;
}

// grab content encoding header

String HTTPHeader::contentEncoding() {
    if (pcontentencoding != NULL) {
        String ce(pcontentencoding->after(": "));
        ce.toLower();
        return ce;
    }
    return ""; // we need a default don't we?
}

// *
// *
// * header modifications
// *
// *

// squid adds this so if more support it it may be useful one day

void HTTPHeader::addXForwardedFor(const std::string &clientip) {
    std::string line("X-Forwarded-For: " + clientip + "\r");
    header.push_back(String(line.c_str()));
}

// set content length header to report given lenth

void HTTPHeader::setContentLength(int newlen) {
    if (pcontentlength != NULL) {
        (*pcontentlength) = "Content-Length: " + String(newlen) + "\r";
    }
}

// set the proxy-connection header to allow persistence (or not)

void HTTPHeader::makePersistent(bool persist) {
    if (persist) {
        // Only make persistent if it originally was, but now isn't.
        // The intention isn't to change browser behaviour, just to
        // un-do any connection downgrading which MinD may have performed
        // earlier.
        if (waspersistent && !ispersistent) {
            if (pproxyconnection != NULL) {
                (*pproxyconnection) = pproxyconnection->before(":") + ": Keep-Alive\r";
            } else {
                if (o.filterworkmode)
                    header.push_back(String("Proxy-Connection: Keep-Alive\r"));
                else
                    header.push_back(String("Connection: Keep-Alive\r"));
                pproxyconnection = &(header.back());
            }
            ispersistent = true;
        }
    } else {
        // Only downgrade to non-persistent if it isn't currently persistent.
        if (ispersistent) {
            if (pproxyconnection != NULL) {
                (*pproxyconnection) = pproxyconnection->before(":") + ": Close\r";
            } else {
                if (o.filterworkmode)
                    header.push_back(String("Proxy-Connection: Close\r"));
                else
                    header.push_back(String("Connection: Close\r"));

                pproxyconnection = &(header.back());
            }
            ispersistent = false;
        }
    }
}

// return a modified accept-encoding header, based on the one supplied,
// but with "identity" added and only supported encodings allowed.

String HTTPHeader::modifyEncodings(String e) {

    // There are 4 types of encoding: gzip, deflate, compress and identity
    // deflate is in zlib format
    // compress is in unix compress format
    // identity is uncompressed and supported by all browsers (obviously)
    // we do not support compress

    e.toLower();
    String o("Accept-Encoding: identity");
#if ZLIB_VERNUM < 0x1210
#warning 'Accept-Encoding: gzip' is disabled
#else
    if (e.contains("gzip")) {
        o += ",gzip";
    }
#endif
    if (e.contains("deflate")) {
        o += ",deflate";
    }

    return o;
}

// set content length to report the given length, and strip content encoding

void HTTPHeader::removeEncoding(int newlen) {
    if (pcontentlength != NULL) {
        (*pcontentlength) = "Content-Length: " + String(newlen) + "\r";
    }
    // this may all be overkill. since we strip everything out of the outgoing
    // accept-encoding header that we don't support, we won't be getting anything
    // back again that we don't support, in theory. leave new code commented
    // unless it proves to be necessary further down the line. PRA 20-10-2005
    if (pcontentencoding != NULL) {
        (*pcontentencoding) = "X-MinD-Removed: Content-Encoding\r";
    }
}

// modifies the URL in all relevant header lines after a regexp search and replace
// setURL Code originally from from Ton Gorter 2004

void HTTPHeader::setURL(String &url) {
    String hostname;
    bool https = (url.before("://") == "https");
    int port = (https ? 443 : 80);

    if (!url.after("://").contains("/")) {
        url += "/";
    }
    hostname = url.after("://").before("/");
    if (hostname.contains("@")) { // Contains a username:password combo
        hostname = hostname.after("@");
    }
    if (hostname.contains(":")) {
        port = hostname.after(":").toInteger();
        if (port == 0 || port > 65535) {
            port = (https ? 443 : 80);
        }
        hostname = hostname.before(":"); // chop off the port bit
    }

#ifdef MIND_DEBUG
    std::cout << "setURL: header.front() changed from: " << header.front() << std::endl;
#endif
    if (!https)
        header.front() = header.front().before(" ") + " " + url + " " + header.front().after(" ").after(" ");
    else
        // Should take form of "CONNECT example.com:443 HTTP/1.0" for SSL
        header.front() = header.front().before(" ") + " " + hostname + ":" + String(port) + " " + header.front().after(" ").after(" ");
#ifdef MIND_DEBUG
    std::cout << " to: " << header.front() << std::endl;
#endif

    if (phost != NULL) {
#ifdef MIND_DEBUG
        std::cout << "setURL: header[] line changed from: " << (*phost) << std::endl;
#endif
        (*phost) = String("Host: ") + hostname;
        if (port != (https ? 443 : 80)) {
            (*phost) += ":";
            (*phost) += String(port);
        }
        (*phost) += "\r";
#ifdef MIND_DEBUG
        std::cout << " to " << (*phost) << std::endl;
#endif
    }
    if (pport != NULL) {
#ifdef MIND_DEBUG
        std::cout << "setURL: header[] line changed from: " << (*pport) << std::endl;
#endif
        (*pport) = String("Port: ") + String(port) + "\r";
#ifdef MIND_DEBUG
        std::cout << " to " << (*pport) << std::endl;
#endif
    }
    // Don't just cache the URL we're sent - url() performs some other
    // processing, notably stripping the port part. Caching here will
    // bypass all that.
    //cachedurl = url.toCharArray();
}

// Does a regexp search and replace.
// urlRegExp Code originally from from Ton Gorter 2004

bool HTTPHeader::regExp(String& line, std::deque<RegExp>& regexp_list, std::deque<String>& replacement_list) {
    RegExp *re;
    String replacement;
    String repstr;
    String newLine;
    bool linemodified = false;
    unsigned int i;
    unsigned int j, k;
    unsigned int s = regexp_list.size();
    unsigned int matches, submatches;
    unsigned int match;
    unsigned int srcoff;
    unsigned int nextoffset;
    unsigned int matchlen;
    unsigned int oldlinelen;

    // iterate over our list of precompiled regexes
    for (i = 0; i < s; i++) {
        newLine = "";
        re = &(regexp_list[i]);
        if (re->match(line.toCharArray())) {
            repstr = replacement_list[i];
            matches = re->numberOfMatches();

            srcoff = 0;

            for (j = 0; j < matches; j++) {
                nextoffset = re->offset(j);
                matchlen = re->length(j);

                // copy next chunk of unmodified data
                if (nextoffset > srcoff) {
                    newLine += line.subString(srcoff, nextoffset - srcoff);
                    srcoff = nextoffset;
                }

                // Count number of submatches (brackets) in replacement string
                for (submatches = 0; j + submatches + 1 < matches; submatches++)
                    if (re->offset(j + submatches + 1) + re->length(j + submatches + 1) > srcoff + matchlen)
                        break;

                // \1 and $1 replacement
                replacement = "";
                for (k = 0; k < repstr.length(); k++) {
                    // find \1..\9 and $1..$9 and fill them in with submatched strings
                    if ((repstr[k] == '\\' || repstr[k] == '$') && repstr[k + 1] >= '1' && repstr[k + 1] <= '9') {
                        match = repstr[++k] - '0';
                        if (match <= submatches) {
                            replacement += re->result(j + match).c_str();
                        }
                    } else {
                        // unescape \\ and \$, and add non-backreference characters to string
                        if (repstr[k] == '\\' && (repstr[k + 1] == '\\' || repstr[k + 1] == '$'))
                            k++;
                        replacement += repstr.subString(k, 1);
                    }
                }

                // copy filled in replacement string
                newLine += replacement;
                srcoff += matchlen;
                j += submatches;
            }
            oldlinelen = line.length();
            if (srcoff < oldlinelen) {
                newLine += line.subString(srcoff, oldlinelen - srcoff);
            }
#ifdef MIND_DEBUG
            std::cout << "Line modified! (" << line << " -> " << newLine << ")" << std::endl;
#endif
            // copy newLine into line and continue with other regexes
            line = newLine;
            linemodified = true;
        }
    }

    return linemodified;
}

// Perform searches and replacements on URL

bool HTTPHeader::urlRegExp(int filtergroup) {
    // exit immediately if list is empty
    if (not o.fg[filtergroup]->url_regexp_list_comp.size())
        return false;
#ifdef MIND_DEBUG
    std::cout << "Starting URL reg exp replace" << std::endl;
#endif
    String newUrl(url());
    if (regExp(newUrl, o.fg[filtergroup]->url_regexp_list_comp, o.fg[filtergroup]->url_regexp_list_rep)) {
        setURL(newUrl);
        return true;
    }
    return false;
}

// Perform searches and replacements on header lines

bool HTTPHeader::headerRegExp(int filtergroup) {
    // exit immediately if list is empty
    if (not o.fg[filtergroup]->header_regexp_list_comp.size())
        return false;
    bool result = false;
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
#ifdef MIND_DEBUG
        std::cout << "Starting header reg exp replace: " << *i << std::endl;
#endif
        bool chop = false;
        if (i->endsWith("\r")) {
            i->chop();
            chop = true;
        }
        result |= regExp(*i, o.fg[filtergroup]->header_regexp_list_comp, o.fg[filtergroup]->header_regexp_list_rep);
        if (chop)
            i->append("\r");
    }
    return result;
}

// *
// *
// * detailed header checks & fixes
// *
// *

// is a URL malformed?

bool HTTPHeader::malformedURL(const String& url) {
    if (!o.filterworkmode)
        return false; // Don't worry about it in simple proxy mode.
    String host(url.after("://"));
    if (host.contains("/"))
        host = host.before("/");
    if (host.length() < 2) {
#ifdef MIND_DEBUG
        std::cout << "host len too small" << std::endl;
#endif
        return true;
    }
    if (host.contains(":"))
        host = host.before(":");
    if (host.contains("..") || host.endsWith(".")) {
#ifdef MIND_DEBUG
        std::cout << "double dots in domain name" << std::endl;
#endif
        return true;
    }
    int i, len;
    unsigned char c;
    len = host.length();
    bool containsletter = false;
    for (i = 0; i < len; i++) {
        c = (unsigned char) host[i];
        // If it contains something other than numbers, dots, or [a-fx] (hex encoded IPs),
        // IP obfuscation can be ruled out.
        if (!containsletter &&
                (((c < '0') || (c > '9'))
                && (c != '.') && (c != 'x') && (c != 'X')
                && ((c < 'a') || (c > 'f'))
                && ((c < 'A') || (c > 'F'))))
            containsletter = true;
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z')
                && !(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '_') {
#ifdef MIND_DEBUG
            std::cout << "bad char in hostname" << std::endl;
#endif
            return true;
            // only allowed letters, digits, hiphen, dots
        }

    }
    // no IP obfuscation going on
    if (containsletter)
        return false;
#ifdef MIND_DEBUG
    else
        std::cout << "Checking for IP obfuscation in " << host << std::endl;
#endif
    // Check no IP obfuscation is going on
    // This includes IPs encoded as a single decimal number,
    // fully or partly hex encoded, and octal encoded
    bool first = true;
    bool obfuscation = false;
    if (host.endsWith("."))
        host.chop();
    do {
        if (!first)
            host = host.after(".");
        first = false;
        String hostpart(host);
        if (host.contains("."))
            hostpart = hostpart.before(".");
        // If any part of the host starts with a letter, any letter,
        // then we must have a hostname rather than an IP (obscured
        // or otherwise).  TLDs never start with a number.
        if ((hostpart[0] >= 'a' && hostpart[0] <= 'z') || (hostpart[0] >= 'A' && hostpart[0] <= 'Z'))
            return false;
        // If any part of the host begins with 0, it may be hex or octal
        if ((hostpart[0] == '0') && (hostpart.length() > 1)) {
            obfuscation = true;
            continue;
        }
        // Also check range, for decimal obfuscation.
        int part = hostpart.toInteger();
        if ((part < 0) || (part > 255))
            obfuscation = true;
    } while (host.contains("."));
    // If we have any obfuscated parts, and haven't proven it's a hostname, it's invalid.
    return obfuscation;
}

// is this a POST request encapsulating a file upload?

bool HTTPHeader::isPostUpload(Socket &peersock) {
    if (header.front().toCharArray()[0] != 'P') {
        return false;
    }
    off_t cl = contentLength();
    if (((cl > 0) && (cl < 14)) || (getContentType() == "application/x-www-form-urlencoded")) {
#ifdef MIND_DEBUG
        std::cout << "Based on content length/type, is not POST upload!" << std::endl;
#endif
        ispostupload = false;
        return false;
    }
    if (getContentType().length() > 0) {
#ifdef MIND_DEBUG
        std::cout << "Based on content length/type, is POST upload!" << std::endl;
#endif
        ispostupload = true;
        return true;
    }

#ifdef MIND_DEBUG
    std::cout << "Reading a line of POST data to determine content type: ";
#endif
    postdatalen = peersock.getLine(postdata, 14, 60, &postdatachopped);
#ifdef MIND_DEBUG
    std::cout << postdata << std::endl;
#endif
    if (postdatalen != 14) {
#ifdef MIND_DEBUG
        std::cout << "Is not POST upload!" << std::endl;
#endif
        ispostupload = false;
        return false;
    }
    String conttype(postdata);
    if (conttype.startsWithLower("content-type: ")) {
#ifdef MIND_DEBUG
        std::cout << "Is POST upload!" << std::endl;
#endif
        ispostupload = true;
        return true;
    } else {
#ifdef MIND_DEBUG
        std::cout << "Is not POST upload!" << std::endl;
#endif
        ispostupload = false;
        return false;
    }
}

void HTTPHeader::modifyClientHeader(bool allowpersistent) {
    String tempString;
    tempString = header.at(0).before(" HTTP/") + " HTTP/1.0\r";
    header.at(0).assign(tempString);

    for (int i = 0; i <= header.size() - 1; i++) {

        if (header.at(i).startsWithLower("host:")) {
            if (!phost) {
                phost = &header.at(i);
                hostName = (String) ((header.at(i).c_str()) + 5);
                if (hostName.contains(":"))
                    hostName = hostName.before(":");
                hostName.removeWhiteSpace();
            } else
                header.at(i).assign("X-MinD-Modified: removed multiple host headers\r");

        } else if (header.at(i).startsWithLower("user-agent:")) {
            if (!puseragent)
                puseragent = &header.at(i);
            else
                header.at(i).assign("X-MinD-Modified: removed multiple user-agent headers\r");

        } else if (header.at(i).startsWithLower("accept-encoding:")) {
            //tempString = "Accept-Encoding:" + header.at(i).after(":");
            header.at(i).assign(modifyEncodings(header.at(i).after(":")) + "\r");

        } else if (header.at(i).startsWithLower("content-type:")) {
            pcontenttype = &header.at(i);

        } else if (header.at(i).startsWithLower("content-length:")) {
            pcontentlength = &header.at(i);
        } else if (header.at(i).startsWithLower("content-disposition:")) {
            pcontentdisposition = &header.at(i);
        } else if ((pproxyauthorization == NULL) &&
                header.at(i).startsWithLower("proxy-authorization:")) {
            pproxyauthorization = &header.at(i);
        } else if ((pproxyconnection == NULL) &&
                (header.at(i).startsWithLower("proxy-connection:")
                || header.at(i).startsWithLower("connection:"))) {
            if (!o.filterworkmode)
                header.at(i).assign("Connection:" + header.at(i).after(":"));
            if (header.at(i).contains("live")) {
                waspersistent = true;
                if (!allowpersistent) {
                    ispersistent = false;
                    header.at(i) = header.at(i).before(":") + ": Close\r";
                } else {
                    ispersistent = true;
                }
            } else {
                ispersistent = false;
                waspersistent = false;
            }
            pproxyconnection = &header.at(i);
        } else if (pxforwardedfor == NULL
                && header.at(i).startsWithLower("x-forwarded-for:")) {
            pxforwardedfor = &header.at(i);
        } else if (pport = NULL && header.at(i).startsWithLower("port:")) {
            pport = &header.at(i);
        }
    }

    if (o.forceGoogleSafeSearch && (phost->startsWith("Host: google.")
            || phost->startsWith("Host: www.google.")
            || phost->startsWith("Host: images.google."))) {
        if (header.front().after("//").after("/").startsWith("search?")
                || header.front().after("//").after("/").startsWith("images?")
                || header.front().after("//").after("/").startsWith("m?")
                || header.front().after("//").after("/").startsWith("m/")
                || header.front().after("/").startsWith("search?")
                || header.front().after("/").startsWith("images?")
                || header.front().after("/").startsWith("m?")
                || header.front().after("/").startsWith("m/")) {
            header.front() = header.front().before(" HTTP/1.0") + "&safe=on HTTP/1.0";
        }
    }

    String newurl(url(true));
    setURL(newurl);
    if (o.filterworkmode == 0) // Simple proxy.
    {
        newurl = "/" + newurl.after("//").after("/");

        if (newurl == "//")
            newurl = "/";

        header.front() = header.front().before(" ")
                + " " + newurl + " HTTP/1.0";
    }

}

void HTTPHeader::modifyServerHeader(bool allowpersistent) {
    for (int i = 0; i <= header.size() - 1; i++) {
        if (header.at(i).startsWithLower("content-type:")) {
            pcontenttype = &header.at(i);

        } else if (header.at(i).startsWithLower("content-length:")) {
            pcontentlength = &header.at(i);
        } else if (header.at(i).startsWithLower("content-disposition:")) {
            pcontentdisposition = &header.at(i);
        } else if ((pcontentencoding == NULL) && header.at(i).startsWithLower("content-encoding:")) {
            pcontentencoding = &header.at(i);
        } else if ((pproxyauthorization == NULL) &&
                header.at(i).startsWithLower("proxy-authorization:")) {
            pproxyauthorization = &header.at(i);
        } else if ((pproxyconnection == NULL) &&
                (header.at(i).startsWithLower("proxy-connection:")
                || header.at(i).startsWithLower("connection:"))) {
            if (header.at(i).contains("live")) {
                waspersistent = true;
                if (!allowpersistent) {
                    ispersistent = false;
                    header.at(i) = header.at(i).before(":") + ": Close\r";
                } else {
                    ispersistent = true;
                }
            } else {
                ispersistent = false;
                waspersistent = false;
            }
            pproxyconnection = &header.at(i);
        }
    }
}

// Modify headers from client and server side.
// For performance reasons we asume there is not HTTP method which starts
// with HT

void HTTPHeader::modifyHeaders(bool allowpersistent) {

    if (header.at(0).after("HTTP/").startsWith("1.1")) {
        waspersistent = true;
        ispersistent = true;
    }

    if (header.at(0).c_str()[0] == 'H' && header.at(0).c_str()[1] == 'T') {
        modifyServerHeader(allowpersistent);
    } else {
        // Inherited from Dansguardian:
        // Do not allow persistent connections on CONNECT requests the browser
        // thinks it has a tunnel directly to the external server,
        // not a connection to the proxy, so it won't be re-used in the manner
        // expected by MinD and will result in waiting for time-outs.
        // Bug originaly identified by Jason Deasi at Dansguardian.
        if (header.at(0).c_str()[0] == 'C') { // CONNECT
            allowpersistent = false;
            modifyClientHeader(false);
        } else
            modifyClientHeader(allowpersistent);
    }

    // if a request was HTTP 1.1 and there was no proxy-connection header, we may need to add one
    if ((!allowpersistent) && ispersistent) {
        // we should only be in this state if pproxyconnection == NULL (otherwise ispersistent will have been falsified earlier)
#ifdef MIND_DEBUG
        std::cout << "CheckHeader: Adding our own Proxy-Connection: Close" << std::endl;
#endif
        if (o.filterworkmode)
            header.push_back("Proxy-Connection: Close\r");
        else
            header.push_back("Connection: Close\r");

        pproxyconnection = &(header.back());
        ispersistent = false;
    } else if (allowpersistent && ispersistent && (pproxyconnection == NULL)) {
#ifdef MIND_DEBUG
        std::cout << "CheckHeader: Adding our own Proxy-Connection: Keep-Alive" << std::endl;
#endif
        // we should only be in this state if HTTP 1.1, persistency allowed, but persistency not explicitly asked for
        if (o.filterworkmode)
            header.push_back("Proxy-Connection: Keep-Alive\r");
        else
            header.push_back("Connection: Keep-Alive\r");

        pproxyconnection = &(header.back());
    }
}

String HTTPHeader::getHost(void) {
    return hostName;
}

// A request may be in the form:
//  GET http://foo.bar:80/ HTML/1.0 (if :80 is omitted 80 is assumed)
// or:
//  GET / HTML/1.0
//  Host: foo.bar (optional header in HTTP/1.0, but like HTTP/1.1, we require it!)
//  Port: 80 (not a standard header; do any clients send it?)
// or:
//  CONNECT foo.bar:443  HTTP/1.1
// So we need to handle all 3

String HTTPHeader::url(bool withport) {
    // Version of URL *with* port is not cached,
    // as vast majority of our code doesn't like
    // port numbers in URLs.
    if (cachedurl.length() > 0 && !withport)
        return cachedurl;
    port = 80;
    bool https = false;
    String hostname;
    String answer(header.front().after(" "));
    answer.removeMultiChar(' ');
    if (answer.after(" ").startsWith("HTTP/")) {
        answer = answer.before(" HTTP/");
    } else {
        answer = answer.before(" http/"); // just in case!
    }
    if (requestType() == "CONNECT") {
        https = true;
        port = 443;
        if (!answer.startsWith("https://")) {
            answer = "https://" + answer;
        }
    }
    if (pport != NULL) {
        port = pport->after(" ").toInteger();
        if (port == 0 || port > 65535)
            port = (https ? 443 : 80);
    }
    if (answer.length()) {
        if (answer[0] == '/') { // must be the latter above
            if (phost != NULL) {
                hostname = phost->after(":");
                hostname.removeWhiteSpace();
                if (hostname.contains(":")) {
                    port = hostname.after(":").toInteger();
                    if (port == 0 || port > 65535) {
                        port = (https ? 443 : 80);
                    }
                    hostname = hostname.before(":");
                }
                while (hostname.endsWith("."))
                    hostname.chop();
                if (withport && (port != (https ? 443 : 80)))
                    hostname += ":" + String(port);
                hostname = "http://" + hostname;
                answer = hostname + answer;
            }
            // Chained proxies need requests in "Proxy" format.
            if (o.filterworkmode == 1)
                header.front() = requestType() + " " + answer + " HTTP/" + header.front().after(" HTTP/");
        } else { // must be in the form GET http://foo.bar:80/ HTML/1.0
            if (!answer.after("://").contains("/")) {
                answer += "/"; // needed later on so correct host is extracted
            }
            String protocol(answer.before("://"));
            hostname = answer.after("://");
            String url(hostname.after("/"));
            url.removeWhiteSpace(); // remove rubbish like ^M and blanks
            if (url.length() > 0) {
                url = "/" + url;
            }
            hostname = hostname.before("/"); // extra / was added 4 here
            if (hostname.contains("@")) { // Contains a username:password combo
                hostname = hostname.after("@");
            }
            if (hostname.contains(":")) {
                port = hostname.after(":").toInteger();
                if (port == 0 || port > 65535) {
                    port = (https ? 443 : 80);
                }
                hostname = hostname.before(":"); // chop off the port bit
            }
            while (hostname.endsWith("."))
                hostname.chop();
            if (withport && (port != (https ? 443 : 80)))
                hostname += ":" + String(port);
            answer = protocol + "://" + hostname + url;
        }
    }
    if (answer.endsWith("//")) {
        answer.chop();
    }
#ifdef MIND_DEBUG
    std::cout << "from header url:" << answer << std::endl;
#endif
    // Don't include port numbers in the URL in the cached version.
    // Most of the code only copes with URLs *without* port specifiers.
    if (!withport)
        cachedurl = answer.toCharArray();
    return answer;
}

// *
// *
// * Bypass URL/Cookie funcs
// *
// *

// chop the GBYPASS or GIBYPASS variable out of a bypass URL
// This function ASSUMES that you really know what you are doing
// Do NOT run this function unless you know that the URL contains a valid bypass code
// Ernest W Lessenger

void HTTPHeader::chopBypass(String url, bool infectionbypass) {
    if (url.contains(infectionbypass ? "GIBYPASS=" : "GBYPASS=")) {
        if (url.contains(infectionbypass ? "?GIBYPASS=" : "?GBYPASS=")) {
            String bypass(url.after(infectionbypass ? "?GIBYPASS=" : "?GBYPASS="));
            header.front() = header.front().before(infectionbypass ? "?GIBYPASS=" : "?GBYPASS=") + header.front().after(bypass.toCharArray());
        } else {
            String bypass(url.after(infectionbypass ? "&GIBYPASS=" : "&GBYPASS="));
            header.front() = header.front().before(infectionbypass ? "&GIBYPASS=" : "&GBYPASS=") + header.front().after(bypass.toCharArray());
        }
    }
    cachedurl = "";
}

// same for scan bypass

void HTTPHeader::chopScanBypass(String url) {
    if (url.contains("GSBYPASS=")) {
        if (url.contains("?GSBYPASS=")) {
            String bypass(url.after("?GSBYPASS="));
            header.front() = header.front().before("?GSBYPASS=") + header.front().after(bypass.toCharArray());
        } else {
            String bypass(url.after("&GSBYPASS="));
            header.front() = header.front().before("&GSBYPASS=") + header.front().after(bypass.toCharArray());
        }
    }
    cachedurl = "";
}

// I'm not proud of this... --Ernest

String HTTPHeader::getCookie(const char *cookie) {
    String line;
    // TODO - do away with loop here somehow, or otherwise speed it up?
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
        if (i->startsWithLower("cookie:")) {
            line = i->after(": ");
            if (line.contains(cookie)) { // We know we have the cookie
                line = line.after(cookie);
                line.lop(); // Get rid of the '='
                if (line.contains(";")) {
                    line = line.before(";");
                }
            }
            // break;  // Technically there should be only one Cookie: header, but...
        }
    }
    line.removeWhiteSpace();
#ifdef MIND_DEBUG
    std::cout << "Found GBYPASS cookie:" << line << std::endl;
#endif
    return line;
}

// add cookie with given name & value to outgoing headers

void HTTPHeader::setCookie(const char *cookie, const char *domain, const char *value) {
    String line("Set-Cookie: ");
    line += cookie;
    line += "=";
    line += value;
    line += "; path=/; domain=.";
    line += domain;
    line += "\r";
    header.push_back(line);
#ifdef MIND_DEBUG
    std::cout << "Setting cookie:" << line << std::endl;
#endif
    // no expiry specified so ends with the browser session
}

// is this a temporary filter bypass cookie?

bool HTTPHeader::isBypassCookie(String url, const char *magic, const char *clientip) {
    String cookie(getCookie("GBYPASS"));
    if (!cookie.length()) {
#ifdef MIND_DEBUG
        std::cout << "No bypass cookie" << std::endl;
#endif
        return false;
    }
    String cookiehash(cookie.subString(0, 32));
    String cookietime(cookie.after(cookiehash.toCharArray()));
    String mymagic(magic);
    mymagic += clientip;
    mymagic += cookietime;
    bool matched = false;
    while (url.contains(".")) {
        String hashed(url.md5(mymagic.toCharArray()));
        if (hashed == cookiehash) {
            matched = true;
            break;
        }
        url = url.after(".");
    }
    if (not matched) {
#ifdef MIND_DEBUG
        std::cout << "Cookie GBYPASS not match" << std::endl;
#endif
        return false;
    }
    time_t timen = time(NULL);
    time_t timeu = cookietime.toLong();
    if (timeu < timen) {
#ifdef MIND_DEBUG
        std::cout << "Cookie GBYPASS expired: " << timeu << " " << timen << std::endl;
#endif
        return false;
    }
    return true;
}

// is this a temporary filter bypass URL?

int HTTPHeader::isBypassURL(String * url, const char *magic, const char *clientip, bool *isvirusbypass) {
    if ((*url).length() <= 45)
        return false; // Too short, can't be a bypass

    // check to see if this is a bypass URL, and which type it is
    bool filterbypass = false;
    bool virusbypass = false;
    if ((isvirusbypass == NULL) && ((*url).contains("GBYPASS="))) {
        filterbypass = true;
    } else if ((isvirusbypass != NULL) && (*url).contains("GIBYPASS=")) {
        virusbypass = true;
    }
    if (!(filterbypass || virusbypass))
        return 0;

#ifdef MIND_DEBUG
    std::cout << "URL " << (filterbypass ? "GBYPASS" : "GIBYPASS") << " found checking..." << std::endl;
#endif

    String url_left((*url).before(filterbypass ? "GBYPASS=" : "GIBYPASS="));
    url_left.chop(); // remove the ? or &
    String url_right((*url).after(filterbypass ? "GBYPASS=" : "GIBYPASS="));

    String url_hash(url_right.subString(0, 32));
    String url_time(url_right.after(url_hash.toCharArray()));
#ifdef MIND_DEBUG
    std::cout << "URL: " << url_left << ", HASH: " << url_hash << ", TIME: " << url_time << std::endl;
#endif

    String mymagic(magic);
    mymagic += clientip;
    mymagic += url_time;
    String hashed(url_left.md5(mymagic.toCharArray()));

    if (hashed != url_hash) {
#ifdef MIND_DEBUG
        std::cout << "URL " << (filterbypass ? "GBYPASS" : "GIBYPASS") << " hash mismatch" << std::endl;
#endif
        return 0;
    }

    time_t timen = time(NULL);
    time_t timeu = url_time.toLong();

    if (timeu < 1) {
#ifdef MIND_DEBUG
        std::cout << "URL " << (filterbypass ? "GBYPASS" : "GIBYPASS") << " bad time value" << std::endl;
#endif
        return 1; // bad time value
    }
    if (timeu < timen) { // expired key
#ifdef MIND_DEBUG
        std::cout << "URL " << (filterbypass ? "GBYPASS" : "GIBYPASS") << " expired" << std::endl;
#endif
        return 1; // denotes expired but there
    }
#ifdef MIND_DEBUG
    std::cout << "URL " << (filterbypass ? "GBYPASS" : "GIBYPASS") << " not expired" << std::endl;
#endif
    if (virusbypass)
        (*isvirusbypass) = true;
    return (int) timeu;
}

// is this a scan bypass URL? i.e. a "magic" URL for retrieving a previously scanned file

bool HTTPHeader::isScanBypassURL(String * url, const char *magic, const char *clientip) {
    if ((*url).length() <= 45)
        return false; // Too short, can't be a bypass

    if (!(*url).contains("GSBYPASS=")) { // If this is not a bypass url
        return false;
    }
#ifdef MIND_DEBUG
    std::cout << "URL GSBYPASS found checking..." << std::endl;
#endif

    String url_left((*url).before("GSBYPASS="));
    url_left.chop(); // remove the ? or &
    String url_right((*url).after("GSBYPASS="));

    String url_hash(url_right.subString(0, 32));
#ifdef MIND_DEBUG
    std::cout << "URL: " << url_left << ", HASH: " << url_hash << std::endl;
#endif

    // format is:
    // GSBYPASS=hash(ip+url+tempfilename+mime+disposition+secret)
    // &N=tempfilename&M=mimetype&D=dispos

    String tempfilename(url_right.after("&N="));
    String tempfilemime(tempfilename.after("&M="));
    String tempfiledis(tempfilemime.after("&D="));
    tempfilemime = tempfilemime.before("&D=");
    tempfilename = tempfilename.before("&M=");

    String tohash(clientip + url_left + tempfilename + tempfilemime + tempfiledis + magic);
    String hashed(tohash.md5());

#ifdef MIND_DEBUG
    std::cout << "checking hash: " << clientip << " " << url_left << " " << tempfilename << " " << " " << tempfilemime << " " << tempfiledis << " " << magic << " " << hashed << std::endl;
#endif

    if (hashed == url_hash) {
        return true;
    }
#ifdef MIND_DEBUG
    std::cout << "URL GSBYPASS HASH mismatch" << std::endl;
#endif

    return false;
}

// *
// *
// * URL and Base64 decoding funcs
// *
// *

// URL decoding (%xx)
// uses regex pre-compiled on startup

String HTTPHeader::decode(const String &s, bool decodeAll) {
    if (s.length() < 3) {
        return s;
    }
#ifdef MIND_DEBUG
    std::cout << "decoding url" << std::endl;
#endif
    if (!urldecode_re.match(s.c_str())) {
        return s;
    } // exit if not found
#ifdef MIND_DEBUG
    std::cout << "matches:" << urldecode_re.numberOfMatches() << std::endl;
    std::cout << "removing %XX" << std::endl;
#endif
    int match;
    int offset;
    int pos = 0;
    int size = s.length();
    String result;
    String n;
    for (match = 0; match < urldecode_re.numberOfMatches(); match++) {
        offset = urldecode_re.offset(match);
        if (offset > pos) {
            result += s.subString(pos, offset - pos);
        }
        n = urldecode_re.result(match).c_str();
        n.lop(); // remove %
        result += hexToChar(n, decodeAll);
#ifdef MIND_DEBUG
        std::cout << "encoded: " << urldecode_re.result(match) << " decoded: " << hexToChar(n) << " string so far: " << result << std::endl;
#endif
        pos = offset + 3;
    }
    if (size > pos) {
        result += s.subString(pos, size - pos);
    } else {
        n = "%" + n;
    }
    return result;
}

// turn %xx back into original character

String HTTPHeader::hexToChar(const String &n, bool all) {
    if (n.length() < 2) {
        return String(n);
    }
    static char buf[2];
    unsigned int a, b;
    unsigned char c;
    a = n[0];
    b = n[1];
    if (a >= 'a' && a <= 'f') {
        a -= 87;
    } else if (a >= 'A' && a <= 'F') {
        a -= 55;
    } else if (a >= '0' && a <= '9') {
        a -= 48;
    } else {
        return String("%") + n;
    }
    if (b >= 'a' && b <= 'f') {
        b -= 87;
    } else if (b >= 'A' && b <= 'F') {
        b -= 55;
    } else if (b >= '0' && b <= '9') {
        b -= 48;
    } else {
        return String("%") + n;
    }
    c = a * 16 + b;
    if (all || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-')) {
        buf[0] = c;
        buf[1] = '\0';
        return String(buf);
    } else {
        return String("%") + n;
    }
}

// decode a line of base64

std::string HTTPHeader::decodeb64(const String& line) { // decode a block of b64 MIME
    long four = 0;
    int d;
    std::string result;
    int len = line.length() - 4;
    for (int i = 0; i < len; i += 4) {
        four = 0;
        d = decode1b64(line[i + 0]);
        four = four | d;
        d = decode1b64(line[i + 1]);
        four = (four << 6) | d;
        d = decode1b64(line[i + 2]);
        four = (four << 6) | d;
        d = decode1b64(line[i + 3]);
        four = (four << 6) | d;
        d = (four & 0xFF0000) >> 16;
        result += (char) d;
        d = (four & 0xFF00) >> 8;
        result += (char) d;
        d = four & 0xFF;
        result += (char) d;
    }
    return result;
}

// decode an individual base64 character

int HTTPHeader::decode1b64(char c) {
    unsigned char i = '\0';
    switch (c) {
        case '+':
            i = 62;
            break;
        case '/':
            i = 63;
            break;
        case '=':
            i = 0;
            break;
        default: // must be A-Z, a-z or 0-9
            i = '9' - c;
            if (i > 0x3F) { // under 9
                i = 'Z' - c;
                if (i > 0x3F) { // over Z
                    i = 'z' - c;
                    if (i > 0x3F) { // over z so invalid
                        i = 0x80; // so set the high bit
                    } else {
                        // a-z
                        i = c - 71;
                    }
                } else {
                    // A-Z
                    i = c - 65;
                }
            } else {
                // 0-9
                i = c + 4;
            }
            break;
    }
    return (int) i;
}

// *
// *
// * network send/receive funcs
// *
// *

// send headers out over the given socket
// "reconnect" flag gives permission to reconnect to the socket on write error
// - this allows us to re-open the proxy connection on pconns if squid's end has
// timed out but the client's end hasn't. not much use with NTLM, since squid
// will throw a 407 and restart negotiation, but works well with basic & others.

void HTTPHeader::out(Socket * peersock, Socket * sock, int sendflag, bool reconnect) throw (std::exception) {
    String l; // for amalgamating to avoid conflict with the Nagel algorithm

    if (sendflag == __MIND_HEADER_SENDALL || sendflag == __MIND_HEADER_SENDFIRSTLINE) {
        if (header.size() > 0) {
            l = header.front();
            if (!(l.endsWith("\r") || l.endsWith("\n"))) {
                l += "\r\n";
            } else {
                if (l.endsWith("\r")) {
                    l += "\n";
                }
            }
#ifdef MIND_DEBUG
            std::cout << "headertoclient:" << l << std::endl;
#endif
            // first reconnect loop - send first line
            while (true) {
                if (!(*sock).writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
                    // reconnect & try again if we've been told to
                    if (reconnect) {
                        // don't try more than once
#ifdef MIND_DEBUG
                        log.writeToLog(1, "Proxy connection broken (1); trying to re-establish...");
#endif
                        reconnect = false;
                        sock->reset();
                        int rc = sock->connect(o.proxy_ip, o.proxy_port);
                        if (rc)
                            throw std::exception();
                        continue;
                    }
                    throw std::exception();
                }
                // if we got here, we succeeded, so break the reconnect loop
                break;
            }
        }
        if (sendflag == __MIND_HEADER_SENDFIRSTLINE) {
            return;
        }
    }

    l = "";

    for (std::deque<String>::iterator i = header.begin() + 1; i != header.end(); i++) {
        l += (*i) + "\n";
    }
    l += "\r\n";

#ifdef MIND_DEBUG
    std::cout << "headertoclient:" << l << std::endl;
#endif

    // second reconnect loop
    while (true) {
        // send header to the output stream
        // need exception for bad write

        if (!(*sock).writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
            // reconnect & try again if we've been told to
            if (reconnect) {
                // don't try more than once
#ifdef MIND_DEBUG
                std::cout << "Proxy connection broken (2); trying to re-establish..." << std::endl;
                log.writeToLog, (1"Proxy connection broken (2); trying to re-establish...");
#endif
                reconnect = false;
                sock->reset();
                int rc = sock->connect(o.proxy_ip, o.proxy_port);
                if (rc)
                    throw std::exception();
                // include the first line on the retry
                l = header.front() + "\n" + l;
                continue;
            }
            throw std::exception();
        }
        // if we got here, we succeeded, so break the reconnect loop
        break;
    }

    if ((!requestType().startsWith("HTTP")) && (pcontentlength != NULL)) {
        if (postdatalen > 0) {
#ifdef MIND_DEBUG
            std::cout << "Sending initial POST data chunk" << std::endl;
#endif
            // Re-add the chopped off \n, if necessary
            if (postdatachopped) {
#ifdef MIND_DEBUG
                std::cout << "Re-adding newline to POST data (postdatalen " << postdatalen << ")" << std::endl;
#endif
                postdata[postdatalen - 1] = '\n';
                postdata[postdatalen] = '\0';
            }
            sock->writeToSockete(postdata, postdatalen, 0, timeout);
        }
#ifdef MIND_DEBUG
        std::cout << "Opening tunnel for remainder of POST data" << std::endl;
#endif
        FDTunnel fdt;
        off_t remaining = contentLength() - postdatalen;
        if (remaining < 0)
            throw std::runtime_error("No POST data left to send!?");
        fdt.tunnel(*peersock, *sock, false, remaining, true);
    }
}

// discard remainder of POST data

void HTTPHeader::discard(Socket *sock) {
    static char fred[4096];
    off_t cl = contentLength() - postdatalen;
    int rc;
    while (cl > 0) {
        rc = sock->readFromSocket(fred, ((cl > 4096) ? 4096 : cl), 0, timeout, false);
        if (rc > 0)
            cl -= rc;
        else
            break;
    }
}

void HTTPHeader::in(Socket * sock, bool allowpersistent, bool honour_reloadconfig) {
    if (dirty) reset();
    dirty = true;

    // the RFCs don't specify a max header line length so this should be
    // dynamic really.  Pointed out (well reminded actually) by Daniel Robbins
    char buff[8192]; // setup a buffer to hold the incomming HTTP line
    String line; // temp store to hold the line after processing
    line = "----"; // so we get past the first while
    bool firsttime = true;
    bool discard = false;
    while (line.length() > 3 || discard) { // loop until the stream is
        // failed or we get to the end of the header (a line by itself)

        // get a line of header from the stream
        // on the first time round the loop, honour the reloadconfig flag if desired
        // - this lets us break when waiting for the next request on a pconn, but not
        // during receipt of a request in progress.
        (*sock).getLine(buff, 8192, timeout, firsttime ? honour_reloadconfig : false);

        // getline will throw an exception if there is an error which will
        // only be caught by HandleConnection()

        line = buff; // convert the line to a String

        // ignore crap left in buffer from old pconns (in particular, the IE "extra CRLF after POST" bug)
        discard = false;
        if (not(firsttime && line.length() <= 3))
            header.push_back(line); // stick the line in the deque that holds the header
        else {
            discard = true;
#ifdef MIND_DEBUG
            std::cout << "Discarding unwanted bytes at head of request (pconn closed or IE multipart POST bug)" << std::endl;
#endif
        }
        firsttime = false;
    }
    header.pop_back(); // remove the final blank line of a header
    if (header.size() == 0)
        throw std::exception();

    modifyHeaders(allowpersistent); // sort out a few bits in the header
}
