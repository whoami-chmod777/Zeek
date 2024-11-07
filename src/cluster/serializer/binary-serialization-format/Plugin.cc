#include "Plugin.h"

#include "zeek/cluster/Component.h"

#include "Serializer.h"


using namespace zeek::plugin::Zeek_Binary_Serializer;
using namespace zeek::cluster;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new LogSerializerComponent("ZEEK_BIN_V1", []() -> std::unique_ptr<LogSerializer> {
        return std::make_unique<cluster::detail::BinarySerializationFormatLogSerializer>();
    }));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Binary_Serializer";
    config.description = "Serialization using Zeek's custom binary serialization format";
    return config;
}
