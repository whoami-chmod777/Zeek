#include "RDP.h"
#include "RDPEUDP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_RDP {

class Plugin : public plugin::Plugin {
public:
        plugin::Configuration Configure()
                {
                AddComponent(new ::analyzer::Component("RDP", ::analyzer::rdp::RDP_Analyzer::InstantiateAnalyzer));
                AddComponent(new ::analyzer::Component("RDPEUDP", ::analyzer::rdpeudp::RDPEUDP_Analyzer::InstantiateAnalyzer));

                plugin::Configuration config;
                config.name = "Zeek::RDP";
                config.description = "RDP analyzer";
                return config;
                }
} plugin;

}
}
