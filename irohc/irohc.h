#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

#if defined _WIN32 || defined _WIN64
#define IROHC_IMPORT __declspec(dllimport)
#elif defined __linux__
#define IROHC_IMPORT __attribute__((visibility("default")))
#else
#define IROHC_IMPORT
#endif


extern "C" {

// exists just to prove _anything_ can be called in rust land
int32_t add_numbers(int32_t number1, int32_t number2);

// implementation of the "iroh get-ticket" CLI subcommand
//   @param ticket is the all-in-one ticket string output, eg: IEkcjuPpomMYB0viuenxrRBlQgIRhWWGnXFLjHN7HzaMIMtCQe_7BBGUta9UV3mAzQcmZeCBJS3GnT-dqxpgREb9AQB_AAAB0SIcO19VsSqBsALDFAhAPW1tkqKg6elXf0b2dfxWxpgkwg
//   @param out_path is the path to write the output files to
//   @return is 0 for success, 1 for any kind of error
int32_t get_ticket(const char* ticket, const char* out_path);

} // extern "C"
