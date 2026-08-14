#include <globalplatform/globalplatform.h>

int main(void) {
	return OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA) == NULL;
}
