import ctypes

def cwe_787_example():
    buffer = (ctypes.c_char * 10)()  # Buffer of 10 bytes
    try:
        ctypes.memset(ctypes.addressof(buffer) + 15, ord('A'), 1)  # Out-of-bounds write
        print("CWE-787: Attempted out-of-bounds write")
    except Exception as e:
        print("CWE-787: Error caught during out-of-bounds write attempt:", e)

if __name__ == "__main__":
    cwe_787_example()