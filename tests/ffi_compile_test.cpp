#include "../include/neohook.hpp"
#include <iostream>
#include <cassert>

int main()
{
    try
    {
        std::cout << "Starting NeoHook FFI Link Test..." << std::endl;

        // use C++ wrapper
        neohook::Transaction tx;

        std::cout << "Transaction successfully started." << std::endl;

        tx.abort();
        std::cout << "Transaction successfully aborted." << std::endl;

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}