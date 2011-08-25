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

void showHelp(void);
void executeArgs(int argc, char** argv);
void signalHandler(int signal);
void demonize(void);
pid_t isRunning(void);
void removePidFile(void);
void createPidFile(void);
void setProxyUserAndGroup(void);
void trapSignals(void);
void setCPUaffinity(void);