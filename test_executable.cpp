#include <iostream>
#include <Windows.h>
using namespace std;

int main() {
    int* pi = NULL;
    __try {
        *pi = 0xDEADBEEF;
    }
    __except (true) {
        cout << "Exception caught";
    }

    return 0;
}