from pwn import *
import sys
import shutil

def change_ld(binary, ld):
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None

        
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)

    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0').encode())
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    log.success("PT_INTERP has changed from {} to {}. Generated patched binary in {}".format(data, ld, path)) 
    shutil.copy(path, os.getcwd())
    log.success("Copied patched binary to current directory {}".format(os.getcwd()))
    return ELF(path)

USAGE = """
This script changes the dynamic linker used by a binary to point to a new one. You will need to do this
when you want to LD_PRELOAD a new libc with a binary.

You will need to patch the linker to the same glibc version as the libc you want to load (ex. 2.27).

Ex. If you want to LD_PRELOAD libc-2.27.so, you will need ld-2.27.so. See `glibc_versions` directory for this binary, 
or you can build libc.so and ld.so from glibc source at http://ftp.gnu.org/gnu/libc/

Then run 
`python change-ld.py <elf binary> /full/path/to/ld-2.27.so`

The full path to `ld-2.27.so` cannot be greater than 30 characters or so. Copy the ld.so over to /tmp/ if the script fails to patch the binary.

This will copy the patched binary to the current directory. You can then LD_PRELOAD the new libc as you normally would.
"""

if len(sys.argv) < 3:
    print(USAGE)
    exit()

change_ld(sys.argv[1], sys.argv[2])
