// See the file "COPYING" in the main distribution directory for copyright.

#include "Redis.h"

#include <chrono>

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"

#include "hiredis/async.h"
#include "hiredis/hiredis.h"

static void redisOnConnect(const redisAsyncContext* c, int status) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(c->data);
    backend->OnConnect(status);
}

static void redisOnDisconnect(const redisAsyncContext* c, int status) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(c->data);
    backend->OnDisconnect(status);
}

static void redisAddRead(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnAddRead();
}

static void redisDelRead(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnDelRead();
}

static void redisAddWrite(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnAddWrite();
}

static void redisDelWrite(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnDelWrite();
}

static void redisCleanup(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnCleanup();
}

namespace zeek::storage::backends::redis {
storage::Backend* Redis::Instantiate() { return new Redis(); }

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult Redis::DoOpen(RecordValPtr config) {
    redisOptions opt = {0};

    StringValPtr address = config->GetField<StringVal>("server_addr");
    if ( address ) {
        PortValPtr port = config->GetField<PortVal>("server_port");
        server_addr = util::fmt("%s:%d", address->ToStdStringView().data(), port->Port());
        REDIS_OPTIONS_SET_TCP(&opt, address->ToStdStringView().data(), port->Port());
    }
    else {
        StringValPtr unix_sock = config->GetField<StringVal>("server_unix_socket");
        server_addr = address->ToStdString();
        REDIS_OPTIONS_SET_UNIX(&opt, unix_sock->ToStdStringView().data());
    }

    opt.options |= REDIS_OPT_PREFER_IPV4;
    opt.options |= REDIS_OPT_NOAUTOFREEREPLIES;

    struct timeval timeout = {5, 0};
    opt.connect_timeout = &timeout;

    ctx = redisAsyncConnectWithOptions(&opt);
    if ( ctx == nullptr || ctx->err ) {
        std::string errmsg = util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());

        if ( ctx ) {
            errmsg.append(": ");
            errmsg.append(ctx->errstr);
        }

        redisAsyncFree(ctx);
        ctx = nullptr;
        return errmsg;
    }

    ctx->data = this;
    ctx->ev.data = this;
    ctx->ev.addRead = redisAddRead;
    ctx->ev.delRead = redisDelRead;
    ctx->ev.addWrite = redisAddWrite;
    ctx->ev.delWrite = redisDelWrite;
    ctx->ev.cleanup = redisCleanup;

    redisAsyncSetConnectCallback(ctx, redisOnConnect);
    redisAsyncSetDisconnectCallback(ctx, redisOnDisconnect);

    key_prefix = config->GetField<StringVal>("key_prefix")->ToStdString();
    op_timeout = std::chrono::microseconds(static_cast<long>(config->GetField<IntervalVal>("op_timeout")->Get() * 1e6));

    return std::nullopt;
}

void Redis::OnConnect(int status) {
    on_connect_called = true;
    if ( status == REDIS_OK ) {
        printf("Connected\n");
        connected = true;
        return;
    }

    reporter->Error("Redis backend failed to connect: %s", ctx->errstr);

    // TODO: we could attempt to reconnect here
}

/**
 * Finalizes the backend when it's being closed.
 */
void Redis::Done() {
    if ( ctx ) {
        redisAsyncDisconnect(ctx);
        redisAsyncFree(ctx);
        ctx = nullptr;
        connected = false;
    }
}

void Redis::OnDisconnect(int status) {
    printf("Disconnecting\n");
    if ( status == REDIS_OK ) {
        // TODO: this was an intentional disconnect, nothing to do?
    }
    else {
        // TODO: this was unintentional, should we reconnect?
    }

    connected = false;
}

static void redisPut(redisAsyncContext* ctx, void* reply, void* privdata) {
    Redis::OpData* opdata = static_cast<Redis::OpData*>(privdata);
    opdata->backend->HandlePutResult(opdata->index, static_cast<redisReply*>(reply),
                                     static_cast<ErrorResultCallback*>(opdata->callback));
    delete opdata;
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult Redis::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    printf("DoPut\n");
    if ( ! ctx ) {
        printf("Connection is not open\n");
        return "Connection is not open";
    }

    std::string format = "SET %s:%s %s";
    if ( ! overwrite )
        format.append(" NX");
    if ( expiration_time > 0.0 )
        format.append(" PXAT %d");

    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();

    OpData* data = new OpData{++op_index, this, cb};
    int status;
    if ( expiration_time > 0.0 )
        status = redisAsyncCommand(ctx, redisPut, data, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data(), static_cast<uint64_t>(expiration_time * 1e6));
    else
        status = redisAsyncCommand(ctx, redisPut, data, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Put operation failed: %s", ctx->errstr);

    return std::nullopt;
}

void Redis::HandlePutResult(uint64_t index, redisReply* reply, ErrorResultCallback* callback) {
    if ( ! connected )
        return;

    ErrorResult res;
    if ( reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Put operation failed: %s", reply->str);

    freeReplyObject(reply);
    callback->Complete(res);
}

static void redisGet(redisAsyncContext* ctx, void* reply, void* privdata) {
    Redis::OpData* opdata = static_cast<Redis::OpData*>(privdata);
    opdata->backend->HandleGetResult(opdata->index, static_cast<redisReply*>(reply),
                                     static_cast<ValResultCallback*>(opdata->callback));
    delete opdata;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult Redis::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! ctx )
        return nonstd::unexpected<std::string>("Connection is not open");

    auto json_key = key->ToJSON()->ToStdString();

    OpData* data = new OpData{++op_index, this, cb};
    int status = redisAsyncCommand(ctx, redisGet, data, "GET %s:%s", key_prefix.data(), json_key.data());

    if ( connected && status == REDIS_ERR )
        return nonstd::unexpected<std::string>(util::fmt("Get operation failed: %s", ctx->errstr));

    return nullptr;
}

void Redis::HandleGetResult(uint64_t index, redisReply* reply, ValResultCallback* callback) {
    if ( ! connected )
        return;

    ValResult res;
    if ( reply->type == REDIS_REPLY_NIL )
        res = nonstd::unexpected<std::string>("key not found");
    else {
        auto val = zeek::detail::ValFromJSON(reply->str, val_type, Func::nil);
        freeReplyObject(reply);

        if ( std::holds_alternative<ValPtr>(val) ) {
            ValPtr val_v = std::get<ValPtr>(val);
            res = val_v;
        }
        else {
            res = nonstd::unexpected<std::string>(std::get<std::string>(val));
        }
    }

    callback->Complete(res);
}

static void redisErase(redisAsyncContext* ctx, void* reply, void* privdata) {
    Redis::OpData* opdata = static_cast<Redis::OpData*>(privdata);
    opdata->backend->HandleEraseResult(opdata->index, static_cast<redisReply*>(reply),
                                       static_cast<ErrorResultCallback*>(opdata->callback));
    delete opdata;
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult Redis::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    auto json_key = key->ToJSON()->ToStdString();

    OpData* data = new OpData{++op_index, this, cb};
    int status = redisAsyncCommand(ctx, redisErase, data, "DEL %s:%s", key_prefix.data(), json_key.data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Erase operation failed: %s", ctx->errstr);

    return std::nullopt;
}

void Redis::HandleEraseResult(uint64_t index, redisReply* reply, ErrorResultCallback* callback) {
    if ( ! connected )
        return;

    ErrorResult res;
    if ( reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Erase operation failed: %s", reply->str);

    freeReplyObject(reply);
    callback->Complete(res);
}

void Redis::ProcessFd(int fd, int flags) {
    if ( flags == IOSource::READ ) {
        printf("got read\n");
        redisAsyncHandleRead(ctx);
    }
    else if ( flags == IOSource::WRITE ) {
        printf("got write\n");
        redisAsyncHandleWrite(ctx);
    }
}

void Redis::OnAddRead() {
    printf("add read %d\n", ctx->c.fd);
    if ( reading )
        return;

    iosource_mgr->RegisterFd(ctx->c.fd, this, IOSource::READ);
    reading = true;
}

void Redis::OnDelRead() {
    printf("del read %d\n", ctx->c.fd);
    if ( ! reading )
        return;

    iosource_mgr->UnregisterFd(ctx->c.fd, this, IOSource::READ);
    reading = false;
}

void Redis::OnAddWrite() {
    printf("add write %d\n", ctx->c.fd);
    if ( writing )
        return;

    iosource_mgr->RegisterFd(ctx->c.fd, this, IOSource::WRITE);
    writing = true;
}

void Redis::OnDelWrite() {
    printf("del write %d\n", ctx->c.fd);
    if ( ! writing )
        return;

    iosource_mgr->UnregisterFd(ctx->c.fd, this, IOSource::WRITE);
    writing = false;
}

void Redis::OnCleanup() {
    OnDelRead();
    OnDelWrite();
}

} // namespace zeek::storage::backends::redis
