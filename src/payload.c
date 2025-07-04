#include <windows.h>
#pragma section("inject", read, execute)

__declspec(code_seg("inject"))
int main_payload(int a) {
    return 2600 + a; // Placeholder for the actual payload logic
}