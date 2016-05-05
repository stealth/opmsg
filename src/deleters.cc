#include <cstdio>
#include "misc.h"

namespace opmsg {

// this wrapper is needed, since fclose() will segfault on NULL
// also remove any locks
extern "C" int ffclose(FILE *f)
{
	if (f) {
		unlockf(f);
		return fclose(f);
	}
	return 0;
}

}
