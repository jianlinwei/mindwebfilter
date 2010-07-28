// LibClamAV content scanning plugin

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
#ifdef HAVE_CONFIG_H
	#include "mind_config.h"
#endif

#include "../ContentScanner.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <clamav.h>
#include <fcntl.h>


// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;


// DECLARATIONS

// class name is relevant!
class clamavinstance:public CSPlugin
{
public:
	clamavinstance(ConfigVar & definition):CSPlugin(definition)
#ifdef HAVE_CLAMAV_SHM
		, use_shm(false)
#endif
		{};

	// we are replacing the inherited scanMemory as it has support for it
	int scanMemory(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
		const char *ip, const char *object, unsigned int objectsize);
	int scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
		const char *ip, const char *filename);

	// could be useful, but doesn't yet do anything - see comments on implementation
	//int scanTest(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup, const char *ip);

	int init(void* args);
	int quit();

private:
	// virus database root node
	// Update to support ClamAV 0.90
	// Based on patch supplied by Aecio F. Neto
	struct cl_engine *root;
	// archive limit options
	struct cl_limits limits;

#ifdef HAVE_CLAMAV_SHM
	// use POSIX shared memory
	bool use_shm;
#endif

	// directory for storing memory buffers (if not shm)
	std::string memdir;

	// convert clamav return value to standard return value
	int doRC(int rc, const char *vn);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

CSPlugin *clamavcreate(ConfigVar & definition)
{
	return new clamavinstance(definition);
}

// end of Class factory

// destroy plugin
int clamavinstance::quit()
{
	cl_free(root);
	return MIND_CS_OK;
}

// does the given request need virus scanning?
// this could do clever things to return true only when something matches the
// options we pass to libclamav - but for now, it just calls the default,
// and so is unnecessary. PRA 13-10-2005
/*int clamavinstance::scanTest(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup, const char *ip)
{
	return CSPlugin::scanTest(requestheader, docheader, user, filtergroup, ip);
}*/

// override the inherited scanMemory, since libclamav can actually scan memory areas directly
// ... but we don't want it to! cl_scanbuff is crippled (no archive unpacking, only basic signature scanning)
// and scheduled for removal. instead, use shm_open to create an "in memory" file, and use cl_scandesc.
// !!! this may not prove to be very portable !!!
int clamavinstance::scanMemory(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user,
	int filtergroup, const char *ip, const char *object, unsigned int objectsize)
{
	lastmessage = lastvirusname = "";
	const char *vn = NULL;
	int fd;
	std::string fname;

#ifdef HAVE_CLAMAV_SHM
	if (use_shm) {
		// use POSIX shared memory to get the FD
		fname = tmpnam(NULL);
		fname = fname.substr(fname.find_last_of('/'));
		fd = shm_open(fname.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
	} else {
#endif
		fname = memdir + "/tfXXXXXX";
		char* fnamearray = new char[fname.length() + 1];
		strcpy(fnamearray, fname.c_str());
		fd = mkstemp(fnamearray);
		fname = fnamearray;
		delete[] fnamearray;
#ifdef HAVE_CLAMAV_SHM
	}
#endif

#ifdef MIND_DEBUG
	std::cout << "Clamav plugin buffer store: " << fname << std::endl;
#endif

	if (fd == -1) {
#ifdef MIND_DEBUG
		std::cerr << "ClamAV plugin error during buffer store creation: " << fname << ", " << strerror(errno) << std::endl;
#endif
		syslog(LOG_ERR, "ClamAV plugin error during buffer store creation: %s, %s", fname.c_str(), strerror(errno));
		return MIND_CS_SCANERROR;
	}

	int rc = write(fd, object, objectsize);
	if (fd == -1) {
#ifdef MIND_DEBUG
		std::cerr << "ClamAV plugin error during write: " << strerror(errno) << std::endl;
#endif
		syslog(LOG_ERR, "ClamAV plugin error during write: %s", strerror(errno));
		return MIND_CS_SCANERROR;
	}

	rc = cl_scandesc(fd, &vn, NULL, root, &limits, CL_SCAN_STDOPT);
	close(fd);

#ifdef HAVE_CLAMAV_SHM
	if (use_shm)
		fd = shm_unlink(fname.c_str());
	else
#endif
		fd = unlink(fname.c_str());

	if (fd == -1) {
#ifdef MIND_DEBUG
		std::cerr << "ClamAV plugin error during unlink: " << strerror(errno) << std::endl;
#endif
		syslog(LOG_ERR, "ClamAV plugin error during unlink: %s", strerror(errno));
		return MIND_CS_SCANERROR;
	}
	return doRC(rc, vn);
}

// scan given filename
int clamavinstance::scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup, const char *ip, const char *filename)
{
	lastmessage = lastvirusname = "";
	const char *vn = NULL;
	int rc = cl_scanfile(filename, &vn, NULL, root, &limits, CL_SCAN_STDOPT );
	return doRC(rc, vn);
}

// convert libclamav return values into our own standard return values
int clamavinstance::doRC(int rc, const char *vn)
{
	if (rc == CL_VIRUS) {
		lastvirusname = vn;
#ifdef MIND_DEBUG
		std::cerr << "INFECTED! with: " << lastvirusname << std::endl;
#endif
		return MIND_CS_INFECTED;
	}
	else if (rc != CL_CLEAN) {
		lastmessage = cl_strerror(rc);
#ifdef MIND_DEBUG
		std::cerr << "ClamAV error: " << lastmessage << std::endl;
#endif
		syslog(LOG_ERR, "ClamAV error: %s", lastmessage.toCharArray());
		return MIND_CS_SCANERROR;
	}
#ifdef MIND_DEBUG
	std::cerr << "ClamAV - he say yes (clean)" << std::endl;
#endif
	return MIND_CS_CLEAN;
}

// initialise libclamav
int clamavinstance::init(void* args)
{
	// always include these lists
	if (!readStandardLists()) {
		return MIND_CS_ERROR;
	}

	// pick method for storing memory buffers
	String smethod(cv["scanbuffmethod"]);
	if (smethod == "file") {
		memdir = cv["scanbuffdir"].toCharArray();
		if (memdir.length() == 0)
			memdir = o.download_dir;
	}
#ifdef HAVE_CLAMAV_SHM
	else if (smethod == "shm") {
		use_shm = true;
	}
#endif
	else {
		if (!is_daemonised)
			std::cerr << "Unsupported scanbuffmethod: " << smethod << std::endl;
		syslog(LOG_ERR, "Unsupported scanbuffmethod: %s", smethod.toCharArray());
		return MIND_CS_ERROR;
	}

	// set clam's own temp dir
	if (cv["tempdir"].length() > 0)
		cl_settempdir(cv["tempdir"].toCharArray(), 0);

#ifdef MIND_DEBUG
	std::cout << "Scanbuffmethod: " << smethod << std::endl;
	std::cout << "Scanbuffdir: " << memdir << std::endl;
	std::cout << "Tempdir: " << cv["tempdir"] << std::endl;
#endif

	// set file, recursion and compression ratio limits for scanning archives
	root = NULL;
	limits.maxfiles = cv["maxfiles"].toInteger();
	limits.maxfilesize = o.max_content_filecache_scan_size + 1024 * 1024;
	limits.maxreclevel = cv["maxreclevel"].toInteger();
	limits.maxscansize = cv["maxscansize"].toInteger() * 1024;
#ifdef MIND_DEBUG
	std::cerr << "maxfiles: " << limits.maxfiles << " maxfilesize: " << limits.maxfilesize
		<< " maxreclevel: " << limits.maxreclevel << " maxscansize: " << limits.maxscansize << std::endl;
#endif

	// load virus database
	unsigned int virnum = 0;
	int rc = cl_load(cl_retdbdir(), &root, &virnum, CL_DB_STDOPT);
#ifdef MIND_DEBUG
	std::cout << "engine: " << root << " virnum: " << virnum << std::endl;
#endif
	if (rc != 0) {
		if (!is_daemonised)
			std::cerr << "Error loading clamav db: " << cl_strerror(rc) << std::endl;
		syslog(LOG_ERR, "Error loading clamav db: %s", cl_strerror(rc));
		return MIND_CS_ERROR;
	}
	rc = cl_build(root);
	if (rc != 0) {
		if (!is_daemonised)
			std::cerr << "Error building clamav db: " << cl_strerror(rc) << std::endl;
		syslog(LOG_ERR, "Error building clamav db: %s", cl_strerror(rc));
		return MIND_CS_ERROR;
	}
	return MIND_CS_OK;
}
