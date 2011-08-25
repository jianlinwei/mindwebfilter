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


#include "RequestHandler.hpp"
#include <stdio.h>

#include "lib/spserver/spporting.hpp"
#include "lib/spserver/sphttp.hpp"
#include "lib/spserver/sphttpmsg.hpp"
#include "lib/spserver/spdispatcher.hpp"
#include "lib/spserver/spioutils.hpp"

CRequestHandler::CRequestHandler() {
}

CRequestHandler::~CRequestHandler() {
}

void CRequestHandler::handle(SP_HttpRequest * request, SP_HttpResponse * response) {
    response->setStatusCode(200);

    response->appendContent("<html><head>"
            "<title>Welcome to simple MinD Blaster</title>"
            "</head><body>MinD Blaster proxy is not developed yet.</body></html>");
}
