
#ifndef BRO_PLUGIN_RLABS_SFLOW
#define BRO_PLUGIN_RLABS_SFLOW

#include <plugin/Plugin.h>

namespace plugin {
namespace RLABS_SFLOW {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
