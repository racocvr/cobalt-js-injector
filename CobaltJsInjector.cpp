/* 
 *  (c) 2013-2016 bugficks
 *
 *  (c) 2015-2017 zoelechat @ SamyGO
 *
 *  (c) 2021 MrB
 *
 *  License: GPLv3
 *
 */
 
///		Usage: samyGOso -n cobalt_launcher -l -r libCobaltJsInjector.so [--args -f <js_file>]
///			
///		args:	-f: full path to the .js file to be executed
///			
///		ex: samyGOso -n cobalt_launcher -r -l $SODIR/libCobaltJsInjector.so --args -f $SYSROOT/usr/share/myfile.js
 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define LIB_VERSION		"v1.0.0"
#define LIB_TV_MODELS	"T"
#define LIB_ISSUE		">>> SamyGO " LIB_TV_MODELS " lib" LIB_NAME " " LIB_VERSION " - (c) zoelechat 2017, MrB 2021 <<<\n"

#define LOG(...)				SGO_LOGI(__VA_ARGS__)

#define AADBG_LOG(FMT, ...)     SGO_LOG(eSGO_LOG_DEBUG, SGO_LOG_TAG, "AADBG", FMT, __VA_ARGS__)
#define HOOK_LOG(L, ...)    SGO_LOG(L, SGO_LOG_TAG, "HOOK", __VA_ARGS__)
#define DYNSYM_LOG(L, ...)    SGO_LOG(L, SGO_LOG_TAG, "DYNSYM", __VA_ARGS__)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <samygo/common.h>
#include <samygo/logging.h>
#include <samygo/samyGOso.h>
#include <samygo/aadbg.h>

#include <samygo/hook_util.h>
#include <samygo/hook.c>

#include <stdarg.h>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <map>

typedef void (*BrowserModule__Reload_t)(void* _this);
BrowserModule__Reload_t BrowserModule__Reload;

void* browser_module = 0;

HOOK_IMPL(int, BrowserModule__OnKeyEventProduced, void* _this, int type, int event)
{		
//	SGO_LOGI("%s: browser_module=0x%08X\n", __func__, _this);
	
	int r = 0;
					
	HOOK_DISPATCH_R(r, BrowserModule__OnKeyEventProduced, _this, type, event);
	
	if(browser_module != _this)
	{
		browser_module = _this;
		BrowserModule__Reload(browser_module);		
	}
			
	return r;
}

char js_file[1024] = {0};

HOOK_IMPL(int, WebModule__ExecuteJavascript, int a1, int a2, const std::string& script_utf8, void* script_location, bool* out_succeeded)
{		
	//SGO_LOGI("%s: a1=0x%08X, a2=0x%08X, script_utf8=%s\n", __func__, a1, a2, script_utf8.c_str());
	
	int r = 0;
	bool succeeded;
		
	std::ifstream ifs(js_file);
	std::string js( (std::istreambuf_iterator<char>(ifs) ), (std::istreambuf_iterator<char>()) );	
							
	HOOK_DISPATCH_R(r, WebModule__ExecuteJavascript, a1, a2, js, script_location, &succeeded);	
	
	if(!succeeded)	
		SGO_LOGI("%s: Script execution failed! Check script file!\n", __func__);
					
	return r;
}

std::string get_fw_version()
{	
	std::ifstream file( "/etc/prd_info.ini");
	std::string   line;
	
	while( std::getline(file, line) )
	{
		std::string::size_type n = line.find("Version=");
		
		if(n != std::string::npos)
			return line.substr(n + 8, line.length() - 8 - 1);
	}
	
	return "unknown version";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int lib_init(void *h, const char *libpath)
{
	std::map<std::string, std::map<std::string, unsigned int>> offset = {
		{ "T-NKLDEUC-1460.9", {
								{ "StarboardMain", 0x6092DC},
								{ "BrowserModule__Reload", 0xD0870},
								{ "BrowserModule__OnKeyEventProduced", 0xD2E94},
								{ "WebModule__ExecuteJavascript", 0x11AEF4},
							}
		},
		{ "T-MSLDEUC-1356.0", {
								{ "StarboardMain", 0x1DEBB8},
								{ "BrowserModule__Reload", 0xD1C64},
								{ "BrowserModule__OnKeyEventProduced", 0xD385C},
								{ "WebModule__ExecuteJavascript", 0x11DEE4},
							}
		}
	};	
	
	std::string model = get_fw_version();	
	
	SGO_LOGD("<%s> h: %p, libpath: %s, model: %s\n", __func__, h, libpath, model.c_str());
	
	if( offset.count(model) < 1 )
	{
		SGO_LOGI("<%s> Offsets for %s not found!\n", __func__, model.c_str());
		return 1;
	}
	
	if(!sgo_lib_check_close(h))
	{
		SGO_LOGI("<%s> Injecting once is enough!\n", __func__);
		return 1;
	}
			
	char *argv[LIB_ARGC_MAX];
	int argc = sgo_getArgCArgV( libpath, argv );
	int opt = 0;
	
	// parse args
	while ( (opt = getopt(argc, argv, "f:")) != -1 )
	{		
		switch(opt)
		{
			case 'f':				
				snprintf(js_file, 1024, "%s", optarg);
				break;			
			
			default:
				break;
		}
	}
	
	struct stat buffer;   
	if (stat (js_file, &buffer) != 0) {
		SGO_LOGI("<%s> error: please specify a valid .js file using the -f argument!\n", __func__);
		return 1;
	}
	SGO_LOGI("Javascript file to load: %s\n", js_file);
		
	// get address of function 'StarboardMain'	
	void* handle = dlopen("/usr/apps/com.samsung.tv.cobalt/bin/libcobalt.so", RTLD_NOW);
	if (handle == NULL) {
		SGO_LOGI("dlopen() failed: %s\n", dlerror());
		return 1;
	}
	
	uint32_t addr = (uint32_t)dlsym(handle, "StarboardMain");	
	if(addr == 0)
	{
		SGO_LOGI("dlsym() failed: %s\n", dlerror());
		return 1;
	}
	
	dlclose(handle);
	
	SGO_LOGI("StarboardMain=0x%08X\n", addr);
	addr -= offset[model]["StarboardMain"];		// module base addr
	
	BrowserModule__Reload = (BrowserModule__Reload_t)(addr + offset[model]["BrowserModule__Reload"]);
	SGO_LOGI("[BrowserModule__Reload:0x%08X]=0x%08X\n", BrowserModule__Reload, *(uint32_t*)BrowserModule__Reload);

	uint32_t BrowserModule__OnKeyEventProduced = addr + offset[model]["BrowserModule__OnKeyEventProduced"];
	SGO_LOGI("[BrowserModule__OnKeyEventProduced:0x%08X]=0x%08X\n", BrowserModule__OnKeyEventProduced, *(uint32_t*)BrowserModule__OnKeyEventProduced);
	
	const uintptr_t pagesize = getpagesize();
    mprotect((void*)SGO_ALIGN_DOWN(BrowserModule__OnKeyEventProduced, pagesize), pagesize * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
	
	hijack_start(&__symhook_BrowserModule__OnKeyEventProduced, (void*)BrowserModule__OnKeyEventProduced, (void*)hook_BrowserModule__OnKeyEventProduced);	
	
	uint32_t WebModule__ExecuteJavascript = addr + offset[model]["WebModule__ExecuteJavascript"];
	SGO_LOGI("[WebModule__ExecuteJavascript:0x%08X]=0x%08X\n", WebModule__ExecuteJavascript, *(uint32_t*)WebModule__ExecuteJavascript);
	
	mprotect((void*)SGO_ALIGN_DOWN(WebModule__ExecuteJavascript, pagesize), pagesize * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
	
	hijack_start(&__symhook_WebModule__ExecuteJavascript, (void*)WebModule__ExecuteJavascript, (void*)hook_WebModule__ExecuteJavascript);	

	SGO_LOGI(">>> Init done\n");
	
	return 0;
}

int lib_deinit(void *h)
{
	SGO_LOGD("<%s> h: %p \n", __func__, h);
	
	hijack_stop(&__symhook_BrowserModule__OnKeyEventProduced);
	hijack_stop(&__symhook_WebModule__ExecuteJavascript);

	SGO_LOGI("<<< Deinit done\n");	
	
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
