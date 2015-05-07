#include <cstdio>

namespace opmsg {

// this wrapper is needed, since fclose() will segfault on NULL
extern "C" int ffclose(FILE *f)
{
	if (f)
		return fclose(f);
	return 0;
}

}
