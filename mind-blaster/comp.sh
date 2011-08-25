#!/bin/bash
set -e
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/sputils.cpp -o sputils.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spioutils.cpp -o spioutils.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spiochannel.cpp -o spiochannel.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spthreadpool.cpp -o spthreadpool.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/event_msgqueue.c -o event_msgqueue.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spbuffer.cpp -o spbuffer.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/sphandler.cpp -o sphandler.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spmsgblock.cpp -o spmsgblock.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spmsgdecoder.cpp -o spmsgdecoder.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spresponse.cpp -o spresponse.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/sprequest.cpp -o sprequest.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spexecutor.cpp -o spexecutor.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spsession.cpp -o spsession.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/speventcb.cpp -o speventcb.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spserver.cpp -o spserver.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spdispatcher.cpp -o spdispatcher.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/splfserver.cpp -o splfserver.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/sphttpmsg.cpp -o sphttpmsg.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/sphttp.cpp -o sphttp.o
gcc -Wall -D_REENTRANT -D_GNU_SOURCE -g -fPIC -c lib/spserver/spsmtp.cpp -o spsmtp.o


gcc -DAPP_VERSION=\"0.1\" -DCONFIGURATION_FILE=\"./mind.cfg\" -g -O0 -o mind -lconfig++ main.cpp RequestHandler.cpp ConfigurationManager.cpp LogManager.cpp sputils.o spioutils.o spiochannel.o spthreadpool.o event_msgqueue.o spbuffer.o sphandler.o spmsgblock.o spmsgdecoder.o spresponse.o sprequest.o spexecutor.o spsession.o speventcb.o spserver.o spdispatcher.o splfserver.o sphttpmsg.o sphttp.o spsmtp.o -lstdc++ -lpthread  -levent -lrt
