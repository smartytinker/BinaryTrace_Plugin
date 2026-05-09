#include <windows.h>
#include <wininet.h>
#include <iostream>

#pragma comment(lib, "wininet.lib")

// 1. Static IOCs (URLs, IPs, Anti-VM)
const char* fake_url = "http://malicious-test.com";
const char* fake_ip = "192.168.100.50";
const char* vm_string1 = "VMware";
const char* vm_string2 = "VBox";

// 2. Fake Decryption Loop (Triggers High Cyclomatic Complexity & XOR rules)
void SuspiciousDecryptionRoutine() {
    // The string "powershell" XOR'd with 0x55
    unsigned char payload[] = {0x25, 0x3a, 0x22, 0x30, 0x27, 0x26, 0x3d, 0x30, 0x39, 0x39};
    
    // This loop forces Binary Ninja to generate HLIL XOR operations
    for(int i = 0; i < 10; i++) {
        payload[i] = payload[i] ^ 0x55;
        if (payload[i] == 0x00) break; 
    }
}

int main() {
    // 3. Evasion & Suspicious APIs
    // We don't actually do anything malicious, but calling them forces 
    // the compiler to put them in the Import Address Table (IAT) for your tool to find.
    
    if (IsDebuggerPresent()) {
        SetUnhandledExceptionFilter(NULL);
    }

    // Networking API (MITRE: Command and Control)
    HINTERNET hInternet = InternetOpenA("Mozilla", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

    // Process Injection API (MITRE: Defense Evasion)
    // Allocating memory in our OWN process is harmless, but statically it looks scary.
    VirtualAllocEx(GetCurrentProcess(), NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Run the fake decryption
    SuspiciousDecryptionRoutine();

    std::cout << "Benign Flag Magnet executed safely." << std::endl;
    return 0;
}