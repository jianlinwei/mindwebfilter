/* 
 * File:   mind.hpp
 *
 * Created on 11 de abril de 2010, 20:10
 */

#ifndef _MIND_HPP
#define	_MIND_HPP

#ifndef FD_SETSIZE
#define FD_SETSIZE 256
#endif

// get the OptionContainer to read in the given configuration file
void read_config(const char *configfile, int type);
void launchSoapServer(char* procName);

#endif	/* _MIND_HPP */

