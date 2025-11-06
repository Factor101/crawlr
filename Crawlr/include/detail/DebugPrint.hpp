#define _DEBUG 1
#ifdef _DEBUG
#define _DEBUG_PRINTF(format, ...) printf(format, ##__VA_ARGS__)
#define _DEBUG_WPRINTF(format, ...) wprintf(format, ##__VA_ARGS__)
#else
	#define _DEBUG_PRINTF(format, ...) ((void)0)
	#define _DEBUG_WPRINTF(format, ...) ((void)0)
#endif
