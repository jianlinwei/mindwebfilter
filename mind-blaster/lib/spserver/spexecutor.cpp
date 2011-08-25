/*
 * This file is part of spserver-0.9.5 Library
 * Modified by MinD Team for MinD Blaster project integration.
 *
 * Copyright 2007 Stephen Liu
 * For license terms, see the file COPYING along with this library.
 *
 * 2011-08 Modified by MinD Team.
 */

#include <sys/types.h>
#include <assert.h>

#include "spporting.hpp"
#include "spexecutor.hpp"
#include "spthreadpool.hpp"
#include "sputils.hpp"
#include "../../LogManager.hpp"

extern CInternalLog internalLog;

SP_Task::~SP_Task() {
}

//===================================================================

SP_SimpleTask::SP_SimpleTask(ThreadFunc_t func, void * arg, int deleteAfterRun) {
    mFunc = func;
    mArg = arg;

    mDeleteAfterRun = deleteAfterRun;
}

SP_SimpleTask::~SP_SimpleTask() {
}

void SP_SimpleTask::run() {
    mFunc(mArg);

    if (mDeleteAfterRun) delete this;
}

//===================================================================

SP_Executor::SP_Executor(int maxThreads, const char * tag) {
    tag = NULL == tag ? "unknown" : tag;

    mThreadPool = new SP_ThreadPool(maxThreads, tag);

    mQueue = new SP_BlockingQueue();

    mIsShutdown = 0;

    sp_thread_mutex_init(&mMutex, NULL);
    sp_thread_cond_init(&mCond, NULL);

    sp_thread_attr_t attr;
    sp_thread_attr_init(&attr);
    assert(sp_thread_attr_setstacksize(&attr, 1024 * 1024) == 0);
    sp_thread_attr_setdetachstate(&attr, SP_THREAD_CREATE_DETACHED);

    sp_thread_t thread;
    int ret = sp_thread_create(&thread, &attr, eventLoop, this);
    sp_thread_attr_destroy(&attr);
    if (ret) {
        internalLog.write(WARNING_MESSAGE,
                "[ex@%s] Unable to create a thread for executor", tag);
    }
}

SP_Executor::~SP_Executor() {
    shutdown();

    while (2 != mIsShutdown) {
        sp_thread_mutex_lock(&mMutex);
        sp_thread_cond_wait(&mCond, &mMutex);
        sp_thread_mutex_unlock(&mMutex);
    }

    sp_thread_mutex_destroy(&mMutex);
    sp_thread_cond_destroy(&mCond);

    delete mThreadPool;
    mThreadPool = NULL;

    delete mQueue;
    mQueue = NULL;
}

void SP_Executor::shutdown() {
    sp_thread_mutex_lock(&mMutex);
    if (0 == mIsShutdown) {
        mIsShutdown = 1;

        // signal the event loop to wake up
        execute(worker, NULL);
    }
    sp_thread_mutex_unlock(&mMutex);
}

sp_thread_result_t SP_THREAD_CALL SP_Executor::eventLoop(void * arg) {
    SP_Executor * executor = (SP_Executor *) arg;

    while (0 == executor->mIsShutdown) {
        void * queueData = executor->mQueue->pop();

        if (executor->mThreadPool->getMaxThreads() > 1) {
            if (0 != executor->mThreadPool->dispatch(worker, queueData)) {
                worker(queueData);
            }
        } else {
            worker(queueData);
        }
    }

    sp_thread_mutex_lock(&executor->mMutex);
    executor->mIsShutdown = 2;
    sp_thread_cond_signal(&executor->mCond);
    sp_thread_mutex_unlock(&executor->mMutex);

    return 0;
}

void SP_Executor::worker(void * arg) {
    if (NULL != arg) {
        SP_Task * task = (SP_Task *) arg;
        task->run();
    }
}

void SP_Executor::execute(SP_Task * task) {
    mQueue->push(task);
}

void SP_Executor::execute(void ( * func) (void *), void * arg) {
    SP_SimpleTask * task = new SP_SimpleTask(func, arg, 1);
    execute(task);
}

int SP_Executor::getQueueLength() {
    return mQueue->getLength();
}

