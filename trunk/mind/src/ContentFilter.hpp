//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb/.com).
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

#ifndef __HPP_NAUGHTYFILTER
#define __HPP_NAUGHTYFILTER


// INCLUDES

#include "String.hpp"
#include "OptionContainer.hpp"
#include "DataBuffer.hpp"


// DECLARATIONS

class ContentFilter
{
public:
	// should the content be blocked?
	bool isItNaughty;
	// should the content bypass any further filtering?
	bool isException;
	// should the browser use the categories string or the displaycategories string?
	// (related to category list thresholding)
	bool usedisplaycats;

	int filtergroup;
	
	// the reason for banning, what to say about it in the logs, and the
	// categories under which banning has taken place
	std::string whatIsNaughty;
	std::string whatIsNaughtyLog;
	std::string whatIsNaughtyCategories;
	std::string whatIsNaughtyDisplayCategories;

	ContentFilter();
	void reset();
	void checkme(DataBuffer * body, String &url, String &domain);
	
	// highest positive (or lowest negative) weighting out of
	// both phrase filtering passes (smart/raw)
	int naughtiness;

private:
	// check the banned, weighted & exception lists
	// pass in both URL & domain to activate embedded URL checking
	// (this is made optional in this manner because it's pointless
	// trying to look for links etc. in "smart" filtering mode, i.e.
	// after HTML has been removed.)
	void checkphrase(char *file, off_t l, String *url = NULL, String *domain = NULL);
	
	// check PICS ratings
	void checkPICS(char *file);
	void checkPICSrating(std::string label);
	void checkPICSratingSafeSurf(String r);
	void checkPICSratingevaluWEB(String r);
	void checkPICSratingCyberNOT(String r);
	void checkPICSratingRSAC(String r);
	void checkPICSratingICRA(String r);
	void checkPICSratingWeburbia(String r);
	void checkPICSratingVancouver(String r);

	// new Korean stuff
	void checkPICSratingICEC(String r);
	void checkPICSratingSafeNet(String r);

	void checkPICSagainstoption(String s, const char *l, int opt, std::string m);
};

#endif
