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


#ifndef REQUESTHANDLER_HPP
#define	REQUESTHANDLER_HPP

#include "lib/spserver/sphttp.hpp"

class CRequestHandler : public SP_HttpHandler {
public:
    CRequestHandler();
    virtual ~CRequestHandler();
    virtual void handle(SP_HttpRequest * request, SP_HttpResponse * response);
private:
};


#endif	/* REQUESTHANDLER_HPP */

