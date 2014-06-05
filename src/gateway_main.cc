#include "config.h"

#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>

#include <string>
#include <vector>

#include "gateway.hh"
#include "vlog.hh"

using namespace std;
using namespace rusv;

namespace
{

Vlog_module lg("main");

void hello(const char* program_name)
{
    printf("gateway %s (%s), compiled " __DATE__ " " __TIME__ "\n", PACKAGE_VERSION,
           program_name);
}

void usage(const char* program_name)
{
    printf("usage: %s...\n", program_name);

    printf("\nOther options:\n"
           "  -v, --verbose           set maximum verbosity level (for console)\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");

    exit(EXIT_SUCCESS);
}

string long_options_to_short_options(const struct option* options)
{
	string short_options;
	for (; options->name; options++)
	{
		const struct option* o = options;
		if (o->flag == NULL && o->val > 0 && o->val <= UCHAR_MAX)
		{
			short_options.push_back(o->val);
			if (o->has_arg == required_argument)
			{
				short_options.push_back(':');
			}
			else if (o->has_arg == optional_argument)
			{
				short_options.append("::");
			}
		}
	}
	return short_options;
}

void set_verbosity(const char* arg)
{
	if (!arg)
	{
		vlog().set_levels(Vlog::FACILITY_CONSOLE, Vlog::ANY_MODULE,
				Vlog::LEVEL_DBG);
	}
	else
	{
		std::string ret;
		ret = vlog().set_levels_from_string(arg);
		if (ret != "ack")
		{
			fprintf(stderr, "error parsing log string: %s\n", ret.c_str());
			exit(EXIT_FAILURE);
		}
	}
}

bool verbose = false;
vector<string> verbosity;

void init_log()
{
	if (verbose)
	{
		set_verbosity(0);
	}
}

} // unnamed namespace

int main(int argc, char *argv[])
{
    /* Program name without full path or "lt-" prefix.  */
    const char *program_name = argv[0];
    if (const char *slash = strrchr(program_name, '/'))
    {
        program_name = slash + 1;
    }
    if (!strncmp(program_name, "lt-", 3))
    {
        program_name += 3;
    }

    for (; ;){
        static struct option long_options[] = {
            {"verbose",     optional_argument, 0, 'v'},
            {"help",        no_argument, 0, 'h'},
            {"version",     no_argument, 0, 'V'},
            {0, 0, 0, 0}
        };

        static string short_options(long_options_to_short_options(long_options));
        int option_index;
        int c;

        c = getopt_long(argc, argv, short_options.c_str(), long_options, &option_index);
        if (c == -1)
            break;

        switch (c){
        case 'h':
            usage(program_name);
            break;

        case 'v':
            if (!optarg)
                verbose = true;
            else
                verbosity.push_back(optarg);
            break;

        case 'V':
            hello(program_name);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }

    if (!verbose)
        hello(program_name);

    init_log();

    for(int i = 0; i < verbosity.size(); i++)
    {
            string& s = verbosity[i];
	    set_verbosity(s.c_str());
    }
    lg.info("Starting %s (%s)", program_name, argv[0]);

	Gateway gw;
	gw.run();

    return 0;
}

