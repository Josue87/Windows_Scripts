from sys import version, exit
from ctypes import *
import argparse
from os.path import isfile
import ctypes.wintypes as wintypes


if not "32 bit" in version:
    print("Process and DLL to injec must be 64 bits")
else:
    print("Process and DLL to injec must be 32 bits")

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", help="Target process", type=int, required=True)
parser.add_argument("-d", "--dll", help="DLL path", required=True)
args = parser.parse_args()

PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = 0x00F0000 | 0x00100000 | 0xFFF
COMMIT_RESERVE = 0x00001000 | 0x00002000

kernel32 = windll.kernel32
pid = int(args.pid)
dll_to_inject = args.dll

if not isfile(dll_to_inject):
    print("%s not found..." %(dll_to_inject))
    exit(0)

dll_len = len(dll_to_inject)

print("(*) Obtaining handle to process with PID %s" %(pid))
handle_p = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

if not handle_p:
    print("(-) OpenProcess function didn't work... Review the PID %s" %(pid))
    exit(0)

print("(*) Assigning space for DLL path")
virtual_mem_allocate = kernel32.VirtualAllocEx(handle_p, 0, dll_len,
                                    COMMIT_RESERVE, PAGE_READWRITE)
if not virtual_mem_allocate:
    print("(-) Error assigning space for DLL")
    exit(0)

print("(*) Writing DLL path")
result = kernel32.WriteProcessMemory(handle_p, virtual_mem_allocate, 
                            dll_to_inject.encode("ascii"), dll_len, 0)
if not result:
    print("(-) Error writing")
    exit(0)

print("(*) Getting LoadLibraryA address")
loadlibA_address = c_void_p.from_buffer(kernel32.LoadLibraryA).value
if not loadlibA_address:
    print("(-) Error getting address")
    print(kernel32.GetLastError())
    exit(0)

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', wintypes.DWORD),
                ('lpSecurityDescriptor', wintypes.LPVOID),
                ('bInheritHandle', wintypes.BOOL),]
thread_id = c_ulong(0)
kernel32.CreateRemoteThread.argtypes = (wintypes.HANDLE, POINTER(_SECURITY_ATTRIBUTES), 
     wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
print("(*) Creating Thread ")
if kernel32.CreateRemoteThread(handle_p, None, 0, loadlibA_address,
                        virtual_mem_allocate, 0, byref(thread_id)):
    print("(+) Remote Thread created!")
else:
    print("(-) DLL could not be injected")