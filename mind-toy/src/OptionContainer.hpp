//Please refer to http://dansguardian.org/?page=copyright2
//
//for the license for this code.
//Written by Daniel Barron (daniel@jadeb.com).
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

#ifndef __HPP_OPTIONCONTAINER
#define __HPP_OPTIONCONTAINER


// INCLUDES

#include "DownloadManager.hpp"
#include "ContentScanner.hpp"
#include "String.hpp"
#include "HTMLTemplate.hpp"
#include "ListContainer.hpp"
#include "ListManager.hpp"
#include "FOptionContainer.hpp"
#include "LanguageContainer.hpp"
#include "ImageContainer.hpp"
#include "RegExp.hpp"
#include "Auth.hpp"
#include "IPList.hpp"

#include <deque>


// DECLARATIONS

class OptionContainer {
public:
    bool forceGoogleSafeSearch;
    bool transparentProxy;
    int filterworkmode;
    char *web_server;
    int blocking_page_ph_style;
    int filter_groups;
    int log_exception_hits;
    bool non_standard_delimiter;
    int weighted_phrase_mode;
    bool show_weighted_found;
    bool forwarded_for;
    bool createlistcachefiles;
    bool use_custom_banned_image;
    std::string custom_banned_image_file;
    bool reverse_lookups;
    bool reverse_client_ip_lookups;
    bool log_client_hostnames;
    bool use_xforwardedfor;
    bool logconerror;
    bool logchildprocs;
    int url_cache_number;
    int url_cache_age;
    int phrase_filter_mode;
    int preserve_case;
    bool hex_decode_content;
    bool force_quick_search;
    int filter_port;
    int proxy_port;
    std::string proxy_ip;
    std::deque<String> filter_ip;
#ifdef ENABLE_ORIG_IP
    bool get_orig_ip;
#endif
    int ll;
    int max_children;
    int min_children;
    int maxspare_children;
    int prefork_children;
    int minspare_children;
    int maxage_children;
    std::string daemon_user_name;
    std::string daemon_group_name;
    int proxy_user;
    int proxy_group;
    int root_user;

    int max_ips;
    bool recheck_replaced_urls;
    bool use_filter_groups_list;
    bool use_group_names_list;
    bool auth_needs_proxy_query;

    std::string languagepath;
    std::string filter_groups_list_location;
    std::string access_denied_address;
    std::string ipc_filename;
    std::string urlipc_filename;
    std::string ipipc_filename;
    std::string pid_filename;

    bool no_daemon;
    bool no_logger;
    unsigned int max_logitem_length;
    bool anonymise_logs;
    bool log_ad_blocks;
    bool log_timestamp;
    bool log_user_agent;
    bool soft_restart;

    std::string daemon_user;
    std::string daemon_group;
    off_t max_upload_size;
    off_t max_content_filter_size;
    off_t max_content_ramcache_scan_size;
    off_t max_content_filecache_scan_size;
    bool scan_clean_cache;
    bool content_scan_exceptions;
    bool delete_downloaded_temp_files;
    std::string download_dir;
    int initial_trickle_delay;
    int trickle_delay;
    int content_scanner_timeout;

    HTMLTemplate html_template;
    ListContainer filter_groups_list;
    IPList exception_ip_list;
    IPList banned_ip_list;
    LanguageContainer language_list;
    ImageContainer banned_image;

    std::deque<Plugin*> dmplugins;
    std::deque<Plugin*> csplugins;
    std::deque<Plugin*> authplugins;
    std::deque<Plugin*>::iterator dmplugins_begin;
    std::deque<Plugin*>::iterator dmplugins_end;
    std::deque<Plugin*>::iterator csplugins_begin;
    std::deque<Plugin*>::iterator csplugins_end;
    std::deque<Plugin*>::iterator authplugins_begin;
    std::deque<Plugin*>::iterator authplugins_end;

    ListManager lm;
    FOptionContainer **fg;
    int numfg;

    // access denied domain (when using the CGI)
    String access_denied_domain;

    bool loadCSPlugins();
    bool loadAuthPlugins();
    void deletePlugins(std::deque<Plugin*> &list);
    void deleteFilterGroups();

    //...and the functions that read them

    OptionContainer();
    ~OptionContainer();
    bool read(const char *filename, int type);
    void reset();
    bool inExceptionIPList(const std::string *ip, std::string *&host);
    bool inBannedIPList(const std::string *ip, std::string *&host);
    bool readFilterGroupConf();
    // public so fc_controlit can reload filter group config files
    bool doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort);

private:
    std::deque<std::string> conffile;
    String conffilename;
    int reporting_level;

    std::string html_template_location;
    std::string group_names_list_location;

    bool loadDMPlugins();

    bool precompileregexps();
    long int findoptionI(const char *option);
    std::string findoptionS(const char *option);
    bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
    bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html);
    std::deque<String> findoptionM(const char *option);

    bool inIPList(const std::string *ip, ListContainer& list, std::string *&host);
};

#endif
