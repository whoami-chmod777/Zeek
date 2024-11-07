// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Backend.h"

#include <optional>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/iosource/Manager.h"
#include "zeek/logging/Manager.h"

using namespace zeek::cluster;

std::string_view detail::Event::HandlerName() const {
    if ( std::holds_alternative<FuncValPtr>(handler) )
        return std::get<FuncValPtr>(handler)->AsFunc()->GetName();

    return std::get<EventHandlerPtr>(handler)->Name();
}

namespace {

std::optional<zeek::Args> check_args(const zeek::FuncValPtr& handler, zeek::ArgsSpan args) {
    const auto& func_type = handler->GetType<zeek::FuncType>();

    if ( func_type->Flavor() != zeek::FUNC_FLAVOR_EVENT ) {
        zeek::reporter->Error("unexpected function type for %s: %s", handler->AsFunc()->GetName().c_str(),
                              func_type->FlavorString().c_str());
        return std::nullopt;
    }

    const auto& types = func_type->ParamList()->GetTypes();
    if ( args.size() != types.size() ) {
        zeek::reporter->Error("bad number of arguments for %s: got %zu, expect %zu",
                              handler->AsFunc()->GetName().c_str(), args.size(), types.size());
        return std::nullopt;
    }

    zeek::Args result(args.size());

    for ( size_t i = 0; i < args.size(); i++ ) {
        const auto& a = args[i];
        const auto& got_type = a->GetType();
        const auto& expected_type = types[i];

        if ( ! same_type(got_type, expected_type) ) {
            zeek::reporter->Error("event parameter #%zu type mismatch, got %s, expecting %s", i,
                                  zeek::obj_desc_short(got_type.get()).c_str(),
                                  zeek::obj_desc_short(expected_type.get()).c_str());
            return std::nullopt;
        }

        result[i] = args[i];
    }

    return result;
}

} // namespace

std::optional<detail::Event> Backend::MakeClusterEvent(FuncValPtr handler, ArgsSpan args, double timestamp) const {
    auto checked_args = check_args(handler, args);
    if ( ! checked_args )
        return std::nullopt;

    return zeek::cluster::detail::Event{handler, std::move(*checked_args), timestamp};
}

zeek::RecordValPtr Backend::DoMakeEvent(zeek::ArgsSpan args) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");
    static const auto& event_record_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    auto rec = zeek::make_intrusive<zeek::RecordVal>(event_record_type);

    if ( args.size() < 1 ) {
        zeek::reporter->Error("not enough arguments to Cluster::make_event()");
        return rec;
    }

    const auto& maybe_func_val = args[0];

    if ( maybe_func_val->GetType()->Tag() != zeek::TYPE_FUNC ) {
        zeek::reporter->Error("attempt to convert non-event into an event type (%s)",
                              zeek::obj_desc_short(maybe_func_val->GetType().get()).c_str());
        return rec;
    }

    const auto func = zeek::FuncValPtr{zeek::NewRef{}, maybe_func_val->AsFuncVal()};
    auto checked_args = check_args(func, args.subspan(1));
    if ( ! checked_args )
        return rec;

    // Making a copy from zeek::Args to a VectorVal and then back again on publish.
    auto vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    vec->Reserve(checked_args->size());
    rec->Assign(0, maybe_func_val);
    for ( const auto& arg : *checked_args )
        vec->Append(arg);

    rec->Assign(1, vec); // Args

    return rec;
}

bool Backend::DoPublishEvent(const std::string& topic, const zeek::RecordValPtr& event) {
    static const auto& event_record_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    if ( event->GetType() != event_record_type ) {
        zeek::emit_builtin_error(zeek::util::fmt("Wrong event type, expected '%s', got '%s'",
                                                 obj_desc(event->GetType().get()).c_str(),
                                                 obj_desc(event_record_type.get()).c_str()));
        return false;
    }

    const auto& rec = cast_intrusive<zeek::RecordVal>(event);
    const auto& func = rec->GetField<zeek::FuncVal>(0);
    const auto& vargs = rec->GetField<VectorVal>(1);
    zeek::Args args(vargs->Size());
    for ( size_t i = 0; i < vargs->Size(); i++ )
        args[i] = vargs->ValAt(i);

    auto ev = cluster::detail::Event(func, std::move(args));

    return PublishEvent(topic, ev);
}

// Default implementation doing the serialization.
bool Backend::DoPublishEvent(const std::string& topic, const cluster::detail::Event& event) {
    cluster::detail::byte_buffer buf;

    if ( ! event_serializer->SerializeEventInto(buf, event) )
        return false;

    return DoPublishEvent(topic, event_serializer->Name(), buf);
}

// Default implementation doing the serialization.
bool Backend::DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                                 zeek::Span<zeek::logging::detail::LogRecord> records) {
    // Serialize the record. This isn't doing any buffering yet.
    //
    // Not clear where the buffering should happen... maybe in
    // the frontend? That would maybe be better for re-usability.
    cluster::detail::byte_buffer buf;

    if ( ! log_serializer->SerializeLogWriteInto(buf, header, records) )
        return false;

    return DoPublishLogWrites(header, log_serializer->Name(), buf);
}

bool Backend::ProcessEventMessage(const std::string_view& topic, const std::string_view& format,
                                  const detail::byte_buffer_span payload) {
    if ( format != event_serializer->Name() ) {
        zeek::reporter->Error("ProcessEventMessage: Wrong format: %s vs %s", std::string{format}.c_str(),
                              event_serializer->Name().c_str());
        return false;
    }

    auto r = event_serializer->UnserializeEvent(payload.data(), payload.size());

    if ( ! r ) {
        auto escaped =
            util::get_escaped_string(std::string(reinterpret_cast<const char*>(payload.data()), payload.size()), false);
        zeek::reporter->Error("Failed to unserialize message: %s: %s", std::string{topic}.c_str(), escaped.c_str());
        return false;
    }

    auto& event = *r;
    zeek::event_mgr.Enqueue(event.Handler(), std::move(event.args), util::detail::SOURCE_BROKER, 0, nullptr,
                            event.timestamp);

    return true;
}

bool Backend::ProcessLogMessage(const std::string_view& format, detail::byte_buffer_span payload) {
    // We could also dynamically lookup the right de-serializer, but
    // for now assume we just receive what is configured.
    if ( format != log_serializer->Name() ) {
        zeek::reporter->Error("Got log message in format '%s', but have deserializer '%s'", std::string{format}.c_str(),
                              log_serializer->Name().c_str());
        return false;
    }

    auto result = log_serializer->UnserializeLogWrite(payload.data(), payload.size());

    if ( ! result ) {
        zeek::reporter->Error("Failed to unserialize log message using '%s'", std::string{format}.c_str());
        return false;
    }

    // Send the whole batch to the logging manager.
    return zeek::log_mgr->WritesFromRemote(result->header, std::move(result->records));
}

bool ThreadedBackend::ProcessBackendMessage(int tag, detail::byte_buffer_span payload) {
    return DoProcessBackendMessage(tag, payload);
}

bool ThreadedBackend::DoInit() { return RegisterIOSource(IOSourceCount::COUNT); }

void ThreadedBackend::DoInitPostScript() { RegisterIOSource(IOSourceCount::DONT_COUNT); }

void ThreadedBackend::QueueForProcessing(QueueMessages&& qmessages) {
    bool fire = false;

    // Enqueue under lock.
    {
        std::scoped_lock lock(messages_mtx);
        fire = messages.empty();

        if ( messages.empty() ) {
            messages = std::move(qmessages);
        }
        else {
            messages.reserve(messages.size() + qmessages.size());
            for ( auto& qmsg : qmessages )
                messages.emplace_back(std::move(qmsg));
        }
    }

    if ( fire )
        messages_flare.Fire();
}

void ThreadedBackend::Process() {
    QueueMessages to_process;
    {
        std::scoped_lock lock(messages_mtx);
        to_process = std::move(messages);
        messages_flare.Extinguish();
        messages.clear();
    }

    for ( const auto& msg : to_process ) {
        // sonarlint wants to use std::visit. not sure...
        if ( auto* emsg = std::get_if<EventMessage>(&msg) ) {
            ProcessEventMessage(emsg->topic, emsg->format, emsg->payload_span());
        }
        else if ( auto* lmsg = std::get_if<LogMessage>(&msg) ) {
            ProcessLogMessage(lmsg->format, lmsg->payload_span());
        }
        else if ( auto* bmsg = std::get_if<BackendMessage>(&msg) ) {
            ProcessBackendMessage(bmsg->tag, bmsg->payload_span());
        }
        else {
            zeek::reporter->FatalError("Unimplemented QueueMessage %zu", msg.index());
        }
    }
}

bool ThreadedBackend::RegisterIOSource(IOSourceCount counts) {
    bool dont_count = counts == IOSourceCount::DONT_COUNT;
    constexpr bool manage_lifetime = true;

    zeek::iosource_mgr->Register(this, dont_count, manage_lifetime);

    if ( ! zeek::iosource_mgr->RegisterFd(messages_flare.FD(), this) ) {
        zeek::reporter->Error("Failed to register messages_flare with IO manager");
        return false;
    }

    return true;
}
