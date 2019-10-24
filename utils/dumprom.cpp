/* (C) 2003 XDA Developers
 * Author: Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xda-developers.com/
 *
 * $Header: /home/cvs/n30/romtools/dumprom.cpp,v 1.1 2005/03/13 19:11:32 wingel Exp $
 */

// for more info on rom layout, see 
//      http://www.xs4all.nl/~itsme/projects/xda/wince-rom-layout.html


// compile with: cl /Wall /wd4710 /wd4217 /wd4668 /wd4820 /EHsc dumprom.cpp nkcompr.lib
// nkcompr.lib is in "/WINCE410/PUBLIC/COMMON/OAK/LIB/X86/RETAIL/nkcompr.lib"

// compiler used is "Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 13.00.9466 for 80x86"
//   ( from visual studio .net )

// some details for my specific rom
// 80000000-80028000 is copied to ram: 8c078000-8c0a0000 - this is the bootloader.
//
// (0x80001000, 0x27000, "boootloader");

// I don't know how to find this other than that is is not referenced anywhere.
// (0x81400000, 0x1284, "rsa sig for all XIP sections");
//    - the header file mentions a ROM_CHAIN_OFFSET, but I don't know how to
//      interpret that.
//    - the xip regions are not very accurate, most are too short.
//       -> the 'end's are only displayed when '-v' is specified.
//
// (0x81900000, 0, "");
// (0x81940000, 0, "");
// (0x81f00000, 0, "saved contacts etc.");
// (0x82000000, 0, "end");
//
// example commandline:
// dumprom rom80000000.bin -x 0x81400000 -u "0x81f00000:0:saved contacts"  -u "0x80001000:0x27000:bootloader" -u "0x81900000:0:" -u "0x81940000:0:" -d tst > info.txt
// 
// some images start at 80040000, in that case you should dump it like this:
// dumprom 3-15-15-ENG-O2euro.nb1 0x80040000
//
// or another one I have has a 1024 byte header, and no bootloader, dump it with:
//
// dumprom ce.img 0x8003fc00
//
// or another one I saw, has a 1024 byte header and a bootloader, dump it with:
//
// dumprom ce_boot.img 0x7ffffc00
//
//
// how to find the file offset:
//
// I may have to automate this. what I do to find this offset, is
// look at where I see "ECEC" -> offset 0x5b
// 
// if "ECEC" is followed by 0x8c0a0000 then this 'ECEC'
// must be the bootloader's, in which case it should be at
// rom-offset 0x80000040 -> use filestart-offset 
//   of 0x80000040-0x5b= 0x7fffffe5
// 
// but in this case, ECEC is followed by an address that is in
// the address range of the rom (0x80000000-0x82000000).
// 
// in that case this 'ECEC' must be at 0x80040040 -> use filestart ofs
//   of 0x80040040-0x5b= 0x8003ffe5
// 

// testing with spv phone rom:
//     - spv phone rom starts at 81c00000
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <vector>
#include <set>
#include <map>

#include <algorithm>
#include <string>
using namespace std;

char *g_outputdirectory=NULL;
int g_verbose=0;

#ifndef _WIN32
typedef bool BOOL;
typedef char CHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef char *LPSTR;
typedef void *LPVOID;
typedef void *PVOID;
typedef BYTE *LPBYTE;

typedef struct _tagFILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;
#define _vsnprintf vsnprintf
#define _snprintf snprintf
#define __int64  long long
#define strnicmp strncasecmp
#else
#include <windows.h>
#endif

class MemoryBlock {
public:
    BYTE *data;
    DWORD length;
    DWORD start;
    DWORD end;

    /* no destructor, to make memory management without copy constructors and refcounting easy */
    /*    I currently don't care about the data buffer leaking */

    bool InRange(DWORD offset) { return (start <= offset && offset < end); }

    bool operator <(const MemoryBlock& mb) const { return start < mb.start; }
    bool operator <(DWORD offset) const { return end < offset; }
};

typedef vector<MemoryBlock> MemoryBlockVector;

class MemoryMapIterator {
public:
    MemoryMapIterator(const MemoryBlockVector::iterator& start, const MemoryBlockVector::iterator& end) 
        : m_end(end)
    {
        m_block= start;
        if (m_block != m_end)
            m_ofs= (*m_block).start;
        else
            m_ofs= 0;
    }
    MemoryMapIterator(const MemoryMapIterator& m)
        : m_end(m.m_end), m_ofs(m.m_ofs), m_block(m.m_block)
    {
    }

    void findnext() 
	{
        while (m_block!=m_end && m_ofs>=(*m_block).end) {
            ++m_block;
        }
        if (m_block==m_end) {
            m_ofs= 0;
        }
        else if (m_ofs<(*m_block).start) {
            m_ofs= (*m_block).start;
        }
    }
    MemoryMapIterator& operator++() // prefix inc
    {
        return *this += 1;
    }
    MemoryMapIterator& operator+=(int stepsize)
    {
        m_ofs+=stepsize;
        findnext();
        return *this;
    }
    bool operator==(const MemoryMapIterator& a) const
    {
        return m_block==a.m_block && m_ofs==a.m_ofs;
    }
    bool operator!=(const MemoryMapIterator& a) const
    {
        return !(*this==a);
    }
    void *GetPtr() const
    {
		if (m_block!=m_end)
			return (*m_block).data+(m_ofs-(*m_block).start);
		else
			return NULL;
    }
    BYTE GetByte() const
    {
        BYTE *p= (BYTE*)GetPtr();
        if (p==NULL)
            return 0;
        return *p;
    }
    DWORD GetWord() const
    {
        WORD *p= (WORD*)GetPtr();
        if (p==NULL)
            return 0;
        return *p;
    }
    DWORD GetDword() const
    {
        BYTE *p= (BYTE*)GetPtr();
        if (p==NULL)
            return 0;
        return *p;
    }

public:
    MemoryBlockVector::iterator m_block;
    DWORD m_ofs;
    const MemoryBlockVector::iterator& m_end;
};

class MemoryMap {
public:
    bool LoadFile(DWORD offset, char *filename, DWORD fileoffset, DWORD length);
    
    void *GetPtr(DWORD offset);
    DWORD GetOfs(void *ptr);
    BYTE GetByte(DWORD offset);
    DWORD GetDword(DWORD offset);

    DWORD FirstAddress();
    DWORD LastAddress();

    MemoryMapIterator begin();
    const MemoryMapIterator end();

private:
    MemoryBlockVector m_blocks;
};
MemoryMap  g_mem;

class MemRegion {
public:
    DWORD start;
    DWORD end;
    DWORD length;
    string *description;

    /* no destructor, to make memory management without copy constructors and refcounting easy */
    /*    I currently don't care about the description buffer leaking */
    MemRegion(DWORD start, DWORD end) : start(start), end(end), description(NULL), length(end-start) {}

    bool operator <(const MemRegion& r) const { return start < r.start || (start==r.start && length<r.length); }

    DWORD FirstNonzero() {
        for (DWORD i=start ; i<end ; ++i)
            if (g_mem.GetByte(i))
                return i;
        return end;
    }
    DWORD LastNonzero() {
        for (DWORD i=end-1 ; i>=start ; --i)
            if (g_mem.GetByte(i))
                return i;
        return start-1;
    }
};

typedef vector<MemRegion> MemRegionVector;
class MemRegions {
public:
    MemRegion& MarkRange(DWORD start, DWORD end, const char *msg, ...);
    MemRegion& MarkRegion(DWORD start, DWORD length, const char *msg, ...);
    MemRegion& MarkRegion_v(DWORD start, DWORD length, const char *msg, va_list ap);

    void DumpMemoryMap();
private:
    MemRegionVector m_list;
};

//--------------------------- global variables
MemRegions g_regions;

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
bool MemoryMap::LoadFile(DWORD offset, char *filename, DWORD fileoffset, DWORD length)
{
    FILE *f= fopen(filename, "rb");
    if (f==NULL)
    {
        perror(filename);
        return false;
    }

    if (length==0)
    {
        if (fseek(f, 0, SEEK_END))
        {
            perror(filename);
            fclose(f);
            return false;
        }

        length= ftell(f)-fileoffset;
    }
    if (length==0)
    {
        fclose(f);
        printf("length not known\n");
        return false;
    }

    MemoryBlock mb;
    mb.data= new BYTE[length];
    if (mb.data==NULL)
    {
        fclose(f);
        printf("error allocating memory\n");
        return false;
    }

    mb.length= length;
    mb.start= offset;
    mb.end= offset+length;

    if (fseek(f, fileoffset, SEEK_SET))
    {
        perror(filename);
        fclose(f);
        return false;
    }

    size_t nRead= fread(mb.data, 1, mb.length, f);
    if (nRead!=mb.length)
    {
        perror("fread");
        fclose(f);
        return false;
    }
    fclose(f);

    // keep m_blocks sorted.
    MemoryBlockVector::iterator i;
    for (i=m_blocks.begin() ; i!=m_blocks.end(); ++i)
        if (mb.start < (*i).start)
            break;

    m_blocks.insert(i, mb);

    if (g_verbose)
        printf("block %ld added buf=%08lx %08lx\n", m_blocks.size(), (DWORD)mb.data, mb.length);
    return true;
}

BYTE MemoryMap::GetByte(DWORD offset)
{
    BYTE *p= (BYTE*)GetPtr(offset);
    if (p==NULL)
        return 0;
    return *p;
}
DWORD MemoryMap::GetDword(DWORD offset)
{
    DWORD *p= (DWORD*)GetPtr(offset);
    if (p==NULL)
        return 0;
    return *p;
}
void *MemoryMap::GetPtr(DWORD offset)
{
    for (MemoryBlockVector::iterator i=m_blocks.begin() ; i!=m_blocks.end(); ++i)
    {
        if ((*i).InRange(offset)) {
            return (*i).data+(offset-(*i).start);
        }
    }
    printf("ERROR: could not find pointer for ofs %08lx\n", offset);
    return NULL;
}
DWORD MemoryMap::GetOfs(void *ptr)
{
    for (MemoryBlockVector::iterator i=m_blocks.begin() ; i!= m_blocks.end() ; ++i)
    {
        if ((*i).data <= ptr && ptr < (*i).data+(*i).length)
        {
            return ((BYTE*)ptr - (*i).data) + (*i).start;
        }
    }
    printf("ERROR: could not find offset for ptr %08lx\n", (DWORD)ptr);
    return 0;
}

DWORD MemoryMap::FirstAddress()
{
    MemoryBlockVector::iterator i=m_blocks.begin();

    return (*i).start;
}
DWORD MemoryMap::LastAddress()
{
    MemoryBlockVector::reverse_iterator i=m_blocks.rbegin();
    return (*i).end;
}
MemoryMapIterator MemoryMap::begin()
{
    return MemoryMapIterator(m_blocks.begin(), m_blocks.end());
}
const MemoryMapIterator MemoryMap::end()
{
    return MemoryMapIterator(m_blocks.end(), m_blocks.end());
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------

MemRegion& MemRegions::MarkRange(DWORD start, DWORD end, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    MemRegion& r= MarkRegion_v(start, end-start, msg, ap);
    va_end(ap);

    return r;
}
MemRegion& MemRegions::MarkRegion(DWORD start, DWORD length, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    MemRegion& r= MarkRegion_v(start, length, msg, ap);
    va_end(ap);

    return r;
}
MemRegion& MemRegions::MarkRegion_v(DWORD start, DWORD length, const char *msg, va_list ap)
{
    char msgbuf[1024];
    _vsnprintf(msgbuf, 1024, msg, ap);

    MemRegion *m= new MemRegion(start, start+length);
    m->description= new string(msgbuf);
    if (m->description==NULL)
    {
        printf("error allocating memory\n");
    }

    m_list.push_back(*m);

    return *m;
}
void bytedump(DWORD start, DWORD end)
{
    for (DWORD ofs= start; ofs<end ; ++ofs)
        printf(" %02x", g_mem.GetByte(ofs));
}
string dworddumpasstring(DWORD start, DWORD end)
{
    string s;
    char buf[10];

    for (DWORD ofs= start ; ofs<(end&~3) ; ofs+=4)
    {
        _snprintf(buf, 10, " %08lx", g_mem.GetDword(ofs));
        s += buf;
    }
    return s;
}

void dworddump(DWORD start, DWORD end)
{
    if (start&3)
    {
        bytedump(start, min(end, (start&~3)+4));

        start= min(end, (start&~3)+4);
    }
    for (DWORD ofs= start ; ofs<(end&~3) ; ofs+=4)
        printf(" %08lx", g_mem.GetDword(ofs));

    if (end&3)
        bytedump(end&~3, end);
}
void MemRegions::DumpMemoryMap()
{
    sort(m_list.begin(), m_list.end());

    DWORD offset= g_mem.FirstAddress();
    for (MemRegionVector::iterator i=m_list.begin() ; i!=m_list.end() ; ++i)
    {
        if (offset < (*i).start) {
            MemRegion m(offset, (*i).start);
            if ( ((*i).start & 3)==0 && (*i).start - offset < 4)
            {
                if (g_verbose>0) {
                    printf("\t%08lx - %08lx L%08lx alignment", m.start, m.end, m.length);
                    if (m.FirstNonzero()!=m.end)
                        bytedump(m.start, m.end);
                }
            }
            else
            {
                DWORD firstnz= max(m.start, m.FirstNonzero() & ~3);
                DWORD lastnz= min(m.end, (m.LastNonzero() & ~3)+4);
                if (firstnz==m.end)
                    printf("\n%08lx - %08lx L%08lx NUL", m.start, m.end, m.length);
                else {
                    if (firstnz != m.start)
                        printf("\n%08lx - %08lx L%08lx NUL", m.start, firstnz, firstnz-m.start);
                    printf("\n%08lx - %08lx L%08lx unknown", firstnz, lastnz, lastnz-firstnz);
                    if (lastnz-firstnz<16)
                        bytedump(firstnz, lastnz);
                    else if (lastnz-firstnz<64)
                        dworddump(firstnz, lastnz);
                    if (lastnz != m.end)
                        printf("\n%08lx - %08lx L%08lx NUL", lastnz, m.end, m.end-lastnz);
                }
            }
        }
        else if (offset > (*i).start) {
            printf("\n!!! overlap of %ld bytes\n", offset-(*i).start );
        }

        printf("\n%08lx - %08lx L%08lx %s", (*i).start, (*i).end, (*i).length, (*i).description->c_str());

        offset= (*i).end;
    }

    if (offset<g_mem.LastAddress())
    {
        printf("\n%08lx - %08lx unknown", offset, g_mem.LastAddress());
    }
    printf("\n");
}
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------

// from DISK2/PUBLIC/COMMON/OAK/INC/PEHDR.H
struct info {                       /* Extra information header block      */
    unsigned long   rva;            /* Virtual relative address of info    */
    unsigned long   size;           /* Size of information block           */
};

// from DISK2/PUBLIC/COMMON/OAK/INC/ROMLDR.H
#define ROM_SIGNATURE_OFFSET 64
#define ROM_SIGNATURE 0x43454345

#define ROM_EXTRA 9

typedef struct e32_rom {
    unsigned short  e32_objcnt;     /* Number of memory objects            */
    unsigned short  e32_imageflags; /* Image flags                         */
    unsigned long   e32_entryrva;   /* Relative virt. addr. of entry point */
    unsigned long   e32_vbase;      /* Virtual base address of module      */
    unsigned short  e32_subsysmajor;/* The subsystem major version number  */
    unsigned short  e32_subsysminor;/* The subsystem minor version number  */

    unsigned long   e32_stackmax;   /* Maximum stack size                  */
    unsigned long   e32_vsize;      /* Virtual size of the entire image    */
    unsigned long	e32_sect14rva;  /* section 14 rva */
    unsigned long	e32_sect14size; /* section 14 size */

    struct info     e32_unit[ROM_EXTRA]; /* Array of extra info units      */
    unsigned short  e32_subsys;     /* The subsystem type                  */
} e32_rom;

// o32_flags
#define IMAGE_SCN_COMPRESSED                 0x00002000  // Section is compressed
typedef struct o32_rom {
    unsigned long       o32_vsize;      /* Virtual memory size              */
    unsigned long       o32_rva;        /* Object relative virtual address  */
    unsigned long       o32_psize;      /* Physical file size of init. data */
    unsigned long       o32_dataptr;    /* Image pages offset               */
    unsigned long   o32_realaddr;       /* pointer to actual                */
    unsigned long       o32_flags;      /* Attribute flags for the object   */
} o32_rom;


typedef struct ROMHDR {
    ULONG   dllfirst;               // first DLL address
    ULONG   dlllast;                // last DLL address
    ULONG   physfirst;              // first physical address
    ULONG   physlast;               // highest physical address
    ULONG   nummods;                // number of TOCentry's
    ULONG   ulRAMStart;             // start of RAM
    ULONG   ulRAMFree;              // start of RAM free space
    ULONG   ulRAMEnd;               // end of RAM
    ULONG   ulCopyEntries;          // number of copy section entries
    ULONG   ulCopyOffset;           // offset to copy section
    ULONG   ulProfileLen;           // length of PROFentries RAM 
    ULONG   ulProfileOffset;        // offset to PROFentries
    ULONG   numfiles;               // number of FILES
    ULONG   ulKernelFlags;          // optional kernel flags from ROMFLAGS .bib config option
    ULONG   ulFSRamPercent;         // Percentage of RAM used for filesystem 
                                        // byte 0 = #4K chunks/Mbyte of RAM for filesystem 0-2Mbytes 0-255
                                        // byte 1 = #4K chunks/Mbyte of RAM for filesystem 2-4Mbytes 0-255
                                        // byte 2 = #4K chunks/Mbyte of RAM for filesystem 4-6Mbytes 0-255
                                        // byte 3 = #4K chunks/Mbyte of RAM for filesystem > 6Mbytes 0-255

    ULONG   ulDrivglobStart;        // device driver global starting address
    ULONG   ulDrivglobLen;          // device driver global length
    USHORT  usCPUType;       		// CPU (machine) Type
    USHORT  usMiscFlags;         	// Miscellaneous flags
	void    *pExtensions;			// pointer to ROM Header extensions
    ULONG   ulTrackingStart;        // tracking memory starting address
    ULONG   ulTrackingLen;          // tracking memory ending address
} ROMHDR;
// followed by nummods <TOCentry>'s
typedef struct TOCentry {           // MODULE BIB section structure
    DWORD dwFileAttributes;
    FILETIME ftTime;
    DWORD nFileSize;
    LPSTR   lpszFileName;
    ULONG   ulE32Offset;            // Offset to E32 structure
    ULONG   ulO32Offset;            // Offset to O32 structure
    ULONG   ulLoadOffset;           // MODULE load buffer offset
} TOCentry, *LPTOCentry;

// followed by numfiles <TOCentry>'s
typedef struct FILESentry {         // FILES BIB section structure
    DWORD dwFileAttributes;
    FILETIME ftTime;
    DWORD nRealFileSize;
    DWORD nCompFileSize;
    LPSTR   lpszFileName;
    ULONG   ulLoadOffset;           // FILES load buffer offset
} FILESentry, *LPFILESentry;

typedef struct COPYentry {
    ULONG   ulSource;               // copy source address
    ULONG   ulDest;                 // copy destination address
    ULONG   ulCopyLen;              // copy length
    ULONG   ulDestLen;              // copy destination length 
                                    // (zero fill to end if > ulCopyLen)
} COPYentry;

// from WINCE410/PUBLIC/COMMON/OAK/INC/ROMLDR.H
#define MAX_ROM                 32      // max numbler of XIPs
#define XIP_NAMELEN             32      // max name length of XIP
#define ROM_CHAIN_OFFSET        0x100   // offset for XIPCHAIN_INFO

typedef struct _XIPCHAIN_ENTRY {
    LPVOID  pvAddr;                 // address of the XIP
    DWORD   dwLength;               // the size of the XIP
    DWORD   dwMaxLength;            // the biggest it can grow to
    USHORT  usOrder;                // where to put into ROMChain_t
    USHORT  usFlags;                // flags/status of XIP
    DWORD   dwVersion;              // version info
    CHAR    szName[XIP_NAMELEN];    // Name of XIP, typically the bin file's name, w/o .bin
    DWORD   dwAlgoFlags;            // algorithm to use for signature verification
    DWORD   dwKeyLen;               // length of key in byPublicKey
    BYTE    byPublicKey[596];       // public key data
} XIPCHAIN_ENTRY, *PXIPCHAIN_ENTRY;

typedef struct _XIPCHAIN_INFO {
    DWORD cXIPs;
    //
    // may contain more than one entry, but we only need the address of first one
    //
    XIPCHAIN_ENTRY xipEntryStart;
} XIPCHAIN_INFO, *PXIPCHAIN_INFO;

#define PID_LENGTH 10
// pointed to by ROMHDR.pExtensions
typedef struct ROMPID {
  union{
    DWORD dwPID[PID_LENGTH];        // PID
    struct {
      char  name[(PID_LENGTH - 4) * sizeof(DWORD)];
      DWORD type;
      PVOID pdata;
      DWORD length;
      DWORD reserved;
    } s;
  };
  PVOID pNextExt;                 // pointer to next extension if any
} ROMPID, EXTENSION;

//----------------output structures [ how pe-exe files are structured ]
//
//  file starts with IMAGE_DOS_HEADER
// 0000000: 5a4d  0090  0003  0000  0004  0000  ffff  0000   MZ..............
// 0000010: 00b8  0000  0000  0000  0040  0000  0000  0000   ........@.......
// 0000020: 0000  0000  0000  0000  0000  0000  0000  0000   ................
// 0000030: 0000  0000  0000  0000  0000  0000  000000c0     ................
//
// followed by some dummy code
// 0000040: 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68  ........!..L.!Th
// 0000050: 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f  is program canno
// 0000060: 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20  t be run in DOS 
// 0000070: 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00  mode....$.......
//
// followed by something unknown
// 0000080: bf 1a f4 da fb 7b 9a 89 fb 7b 9a 89 fb 7b 9a 89  .....{...{...{..
// 0000090: fb 7b 9b 89 fa 7b 9a 89 66 5b ba 89 f8 7b 9a 89  .{...{..f[...{..
// 00000a0: 82 5a be 89 fa 7b 9a 89 52 69 63 68 fb 7b 9a 89  .Z...{..Rich.{..
// 00000b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
//
// followed by a 'e32_exe' struct
// followed by <e32_objcnt> 'o32_obj' structs
// followed by NUL's to align to next 512-byte boundary
// followed by data-sections, each NUL-padded to the next 512-byte boundary
//
// followed by the debug-directory


// also defined in winnt.h
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.
#endif
#define STD_EXTRA       16

// indexes into 'e32_unit'
#define EXP             0           /* Export table position               */
#define IMP             1           /* Import table position               */
#define RES             2           /* Resource table position             */
#define EXC             3           /* Exception table position            */
#define SEC             4           /* Security table position             */
#define FIX             5           /* Fixup table position                */
#define DEB             6           /* Debug table position                */
#define IMD             7           /* Image description table position    */
#define MSP             8           /* Machine specific table position     */
#define TLS             9           /* Thread Local Storage                */
#define CBK            10           /* Callbacks                           */
#define RS1            11           /* Reserved                            */
#define RS2            12           /* Reserved                            */
#define RS3            13           /* Reserved                            */
#define RS4            14           /* Reserved                            */
#define RS5            15           /* Reserved                            */

// value for e32_cpu
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian

// this is the 'FILE HEADER VALUES' in dumpbin output
typedef struct e32_exe {            /* PE 32-bit .EXE header               */
    unsigned char   e32_magic[4];   /* Magic number E32_MAGIC              */
    unsigned short  e32_cpu;        /* The CPU type                        */
    unsigned short  e32_objcnt;     /* Number of memory objects            */
    unsigned long   e32_timestamp;  /* Time EXE file was created/modified  */
    unsigned long   e32_symtaboff;  /* Offset to the symbol table          */

    unsigned long   e32_symcount;   /* Number of symbols                   */
    unsigned short  e32_opthdrsize; /* Optional header size                */
    unsigned short  e32_imageflags; /* Image flags                         */
    unsigned short  e32_coffmagic;  /* Coff magic number (usually 0x10b)   */
    unsigned char   e32_linkmajor;  /* The linker major version number     */
    unsigned char   e32_linkminor;  /* The linker minor version number     */
    unsigned long   e32_codesize;   /* Sum of sizes of all code sections   */

    unsigned long   e32_initdsize;  /* Sum of all initialized data size    */
    unsigned long   e32_uninitdsize;/* Sum of all uninitialized data size  */
    unsigned long   e32_entryrva;   /* Relative virt. addr. of entry point */
    unsigned long   e32_codebase;   /* Address of beginning of code section*/

    unsigned long   e32_database;   /* Address of beginning of data section*/
    unsigned long   e32_vbase;      /* Virtual base address of module      */
    unsigned long   e32_objalign;   /* Object Virtual Address align. factor*/
    unsigned long   e32_filealign;  /* Image page alignment/truncate factor*/

    unsigned short  e32_osmajor;    /* The operating system major ver. no. */
    unsigned short  e32_osminor;    /* The operating system minor ver. no. */
    unsigned short  e32_usermajor;  /* The user major version number       */
    unsigned short  e32_userminor;  /* The user minor version number       */
    unsigned short  e32_subsysmajor;/* The subsystem major version number  */
    unsigned short  e32_subsysminor;/* The subsystem minor version number  */
    unsigned long   e32_res1;       /* Reserved bytes - must be 0  */

    unsigned long   e32_vsize;      /* Virtual size of the entire image    */
    unsigned long   e32_hdrsize;    /* Header information size             */
    unsigned long   e32_filechksum; /* Checksum for entire file            */
    unsigned short  e32_subsys;     /* The subsystem type                  */
    unsigned short  e32_dllflags;   /* DLL flags                           */

    unsigned long   e32_stackmax;   /* Maximum stack size                  */
    unsigned long   e32_stackinit;  /* Initial committed stack size        */
    unsigned long   e32_heapmax;    /* Maximum heap size                   */
    unsigned long   e32_heapinit;   /* Initial committed heap size         */

    unsigned long   e32_res2;       /* Reserved bytes - must be 0  */
    unsigned long   e32_hdrextra;   /* Number of extra info units in header*/
    struct info     e32_unit[STD_EXTRA]; /* Array of extra info units      */
} e32_exe, *LPe32_exe;


// this is the 'section header' in dumpbin output
#define E32OBJNAMEBYTES 8               /* Name bytes                       */

typedef struct o32_obj {                /* .EXE memory object table entry   */
    unsigned char       o32_name[E32OBJNAMEBYTES];/* Object name            */
    unsigned long       o32_vsize;      /* Virtual memory size              */
    unsigned long       o32_rva;        /* Object relative virtual address  */
    unsigned long       o32_psize;      /* Physical file size of init. data */
    unsigned long       o32_dataptr;    /* Image pages offset               */
    unsigned long       o32_realaddr;   /* pointer to actual                */
    unsigned long       o32_access;     /* assigned access                  */
    unsigned long       o32_temp3;
    unsigned long       o32_flags;      /* Attribute flags for the object   */
} o32_obj, *LPo32_obj;


typedef DWORD (*CEDECOMPRESSFN)(LPBYTE BufIn, DWORD InSize, LPBYTE BufOut, DWORD OutSize, DWORD skip, DWORD n, DWORD blocksize);
extern "C" DWORD CEDecompressROM(LPBYTE BufIn, DWORD InSize, LPBYTE BufOut, DWORD OutSize, DWORD skip, DWORD n, DWORD blocksize);
extern "C" DWORD CEDecompress(LPBYTE BufIn, DWORD InSize, LPBYTE BufOut, DWORD OutSize, DWORD skip, DWORD n, DWORD blocksize);
CEDECOMPRESSFN cedecompress= CEDecompress;

#define	CECOMPRESS_ALLZEROS 0
#define	CECOMPRESS_FAILED	0xffffffffUL
#define	CEDECOMPRESS_FAILED	0xffffffffUL

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
/*----------- functions to recreate original file -----------*/

void WriteBlanks(FILE *f, DWORD nblanks)
{
    fseek(f, nblanks, SEEK_CUR);
}
void WriteAlignment(FILE *f, DWORD pagesize)
{
    DWORD curofs= ftell(f);
    if (curofs%pagesize)
        WriteBlanks(f, pagesize-(curofs%pagesize));
}

void WriteDummyMZHeader(FILE *f)
{
    IMAGE_DOS_HEADER dos;
    memset(&dos, 0, sizeof(dos));

    dos.e_magic= IMAGE_DOS_SIGNATURE;
    dos.e_cblp = 0x90;        // Bytes on last page of file
    dos.e_cp   = 3;           // Pages in file
    dos.e_cparhdr= 0x4;       // Size of header in paragraphs
    dos.e_maxalloc= 0xffff;   // Maximum extra paragraphs needed
    dos.e_sp= 0xb8;           // Initial SP value
    dos.e_lfarlc= 0x40;       // File address of relocation table
    dos.e_lfanew= 0xc0;       // File address of new exe header

    BYTE doscode[]= {
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
        0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    fwrite(&dos, 1, sizeof(dos), f);
    fwrite(&doscode, 1, sizeof(doscode), f);

    WriteBlanks(f, 0x40);

    // ftell should be 0xc0 here.
}
DWORD FindFirstSegment(o32_rom *o32, DWORD objcnt, int segtypeflag)
{
    for (DWORD i= 0 ; i<objcnt ; i++)
    {
        if (o32[i].o32_flags&segtypeflag)
            return o32[i].o32_rva;
    }
    return 0;
}
DWORD CalcSegmentSizeSum(o32_rom *o32, DWORD objcnt, int segtypeflag)
{
    DWORD size= 0;
    for (DWORD i= 0 ; i<objcnt ; i++)
    {
        // vsize is not entirely correct, I should use the uncompressed size,
        // but, I don't know that here yet.
        if (o32[i].o32_flags&segtypeflag)
            size += o32[i].o32_vsize;
    }

    return size;
}
DWORD FiletimeToTime_t(FILETIME *pft)
{
    __int64 t; t= pft->dwHighDateTime; t<<=32; t |= pft->dwLowDateTime;

    t /= 10000000LL;
    t -= 11644473600LL;

    return (DWORD)t;
}
void WriteE32Header(FILE *f, e32_rom *e32, TOCentry *t, o32_rom *o32)
{
    e32_exe pe32;
    memset(&pe32, 0, sizeof(pe32));

    pe32.e32_magic[0]= 'P';
    pe32.e32_magic[1]= 'E';
    pe32.e32_cpu= IMAGE_FILE_MACHINE_ARM;
    pe32.e32_objcnt= e32->e32_objcnt;
    pe32.e32_timestamp= FiletimeToTime_t(&t->ftTime);
    pe32.e32_symtaboff=0;
    pe32.e32_symcount=0;
    pe32.e32_opthdrsize= 0xe0;
    pe32.e32_imageflags= e32->e32_imageflags | IMAGE_FILE_RELOCS_STRIPPED;
    pe32.e32_coffmagic= 0x10b;
    pe32.e32_linkmajor= 6;
    pe32.e32_linkminor= 1;
    pe32.e32_codesize= CalcSegmentSizeSum(o32, e32->e32_objcnt, IMAGE_SCN_CNT_CODE);
    pe32.e32_initdsize= CalcSegmentSizeSum(o32, e32->e32_objcnt, IMAGE_SCN_CNT_INITIALIZED_DATA);
    pe32.e32_uninitdsize= CalcSegmentSizeSum(o32, e32->e32_objcnt, IMAGE_SCN_CNT_UNINITIALIZED_DATA);
    pe32.e32_entryrva= e32->e32_entryrva;
    pe32.e32_codebase= FindFirstSegment(o32, e32->e32_objcnt, IMAGE_SCN_CNT_CODE);
    pe32.e32_database= FindFirstSegment(o32, e32->e32_objcnt, IMAGE_SCN_CNT_INITIALIZED_DATA);
    pe32.e32_vbase= e32->e32_vbase;
    pe32.e32_objalign= 0x1000;
    pe32.e32_filealign= 0x200;
    pe32.e32_osmajor= 4;
    pe32.e32_osminor= 0;
    pe32.e32_usermajor;
    pe32.e32_userminor;
    pe32.e32_subsysmajor= e32->e32_subsysmajor;
    pe32.e32_subsysminor= e32->e32_subsysminor;
    pe32.e32_res1;
    pe32.e32_vsize= e32->e32_vsize;
    pe32.e32_hdrsize;    // *** set at a later moment - after alignment is known
    pe32.e32_filechksum= 0;
    pe32.e32_subsys= e32->e32_subsys;
    pe32.e32_dllflags;
    pe32.e32_stackmax= e32->e32_stackmax;
    pe32.e32_stackinit=0x1000; // ?
    pe32.e32_heapmax=0x100000; // ?
    pe32.e32_heapinit=0x1000; // ?

    pe32.e32_res2;
    pe32.e32_hdrextra=STD_EXTRA;   // nr of directories

    pe32.e32_unit[EXP]= e32->e32_unit[EXP];
    pe32.e32_unit[IMP]= e32->e32_unit[IMP];
    pe32.e32_unit[RES]= e32->e32_unit[RES];
    pe32.e32_unit[EXC]= e32->e32_unit[EXC];
    pe32.e32_unit[SEC]= e32->e32_unit[SEC]; // always 0

    // relocation info is always missing
    // pe32.e32_unit[FIX]= e32->e32_unit[FIX];

    // deb struct has pointer outside known filearea
    //pe32.e32_unit[DEB]= e32->e32_unit[DEB];
    pe32.e32_unit[IMD]= e32->e32_unit[IMD]; // always 0
    pe32.e32_unit[MSP]= e32->e32_unit[MSP]; // always 0

    pe32.e32_unit[RS4].rva= e32->e32_sect14rva;
    pe32.e32_unit[RS4].size= e32->e32_sect14size;

    fwrite(&pe32, 1, sizeof(pe32), f);
}
#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define ST_TEXT  0
#define ST_DATA  1
#define ST_PDATA 2
#define ST_RSRC  3
#define ST_OTHER 4
DWORD g_segmentNameUsage[5];
char *g_segmentNames[5]= { ".text", ".data", ".pdata", ".rsrc", ".other" };
void WriteO32Header(FILE *f, const e32_rom *e32, o32_rom *o32)
{
    o32_obj po32;
    memset(&po32, 0, sizeof(po32));

    int segtype;
    if (e32->e32_unit[RES].rva==o32->o32_rva && e32->e32_unit[RES].size==o32->o32_vsize)
        segtype= ST_RSRC;
    else if (e32->e32_unit[EXC].rva==o32->o32_rva && e32->e32_unit[EXC].size==o32->o32_vsize)
        segtype= ST_PDATA;
    else if (o32->o32_flags&IMAGE_SCN_CNT_CODE)
        segtype= ST_TEXT;
    else if (o32->o32_flags&IMAGE_SCN_CNT_INITIALIZED_DATA)
        segtype= ST_DATA;
    else if (o32->o32_flags&IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        segtype= ST_PDATA;
    else
        segtype= ST_OTHER;

    if (g_segmentNameUsage[segtype]) 
    {
        _snprintf((char*)po32.o32_name, 8, "%s%ld", g_segmentNames[segtype], g_segmentNameUsage[segtype]);
    }
    else
    {
        _snprintf((char*)po32.o32_name, 8, "%s", g_segmentNames[segtype]);
    }

    g_segmentNameUsage[segtype]++;

    po32.o32_vsize=         o32->o32_vsize;
    po32.o32_rva=           o32->o32_rva;
    po32.o32_psize=         0; // *** set at a later moment - after uncompressed size is known
    po32.o32_dataptr=       0; // *** set at a later moment - after uncompressed size is known
    po32.o32_realaddr=      0; // file pointer to relocation table
    po32.o32_access=        0; // file pointer to line numbers
    po32.o32_temp3=         0; // number of relocations + number of line numbers
    po32.o32_flags=         o32->o32_flags & ~IMAGE_SCN_COMPRESSED;

    fwrite(&po32, 1, sizeof(po32), f);
}

DWORD WriteUncompressedData(FILE *f, DWORD dataptr, DWORD datasize, BOOL bCompressed, DWORD maxUncompressedSize)
{
    BYTE *buf= (BYTE*)g_mem.GetPtr(dataptr);
    if (buf==NULL)
        return 0;
    DWORD buflen= datasize;
    if (bCompressed) {
        BYTE *dcbuf= new BYTE[maxUncompressedSize+4096];
        buflen= cedecompress(buf, datasize, dcbuf, maxUncompressedSize, 0, 1, 4096);

        if (buflen!=CEDECOMPRESS_FAILED)
        {
            buf= dcbuf;
        }
        else {
            printf("error decompressing %08lxL%08lx\n", dataptr, datasize);
            buflen= datasize;
			bCompressed= false;
			delete dcbuf;
        }
    }

    size_t nWritten= fwrite(buf, 1, buflen, f);
    if (nWritten!=buflen)
    {
        perror("fwrite");
        printf("error writing uncompressed data\n");
    }

    if (bCompressed)
        delete buf;

    return nWritten;
}


void UncompressAndWrite(DWORD start, DWORD end, char *filename, int regnr, BOOL bCompressed, DWORD size, DWORD realofs)
{
    BYTE *buf= (BYTE*)g_mem.GetPtr(start);
    if (buf==NULL)
        return;
    DWORD buflen= end-start;
    if (bCompressed) {
        BYTE *dcbuf= new BYTE[size+4096];
        buflen= cedecompress(buf, end-start, dcbuf, size, 0, 1, 4096);

        if (buflen!=CEDECOMPRESS_FAILED)
        {
            buf= dcbuf;
        }
        else {
            printf("error decompressing %s\n", filename);
            buflen= end-start;
			delete dcbuf;
			bCompressed=false;
        }
    }

    char fn[1024];
    if (regnr<0)
        _snprintf(fn, 1024, "%s\\%s", g_outputdirectory, filename);
    else
        _snprintf(fn, 1024, "%s\\%s-%d-%08lx", g_outputdirectory, filename, regnr, realofs);
    FILE *f= fopen(fn, "w+b");
    if (f==NULL)
    {
        perror(fn);
        if (bCompressed)
            delete buf;
        return;
    }
    DWORD nWritten= fwrite(buf, 1, buflen, f);
    if (nWritten!=buflen)
    {
        printf("error writing %ld bytes - wrote %ld\n", buflen, nWritten);
        perror(fn);
    }
    fclose(f);
    if (bCompressed)
        delete buf;
}

void CreateOriginalFile(TOCentry *t, char *filename, e32_rom *e32, o32_rom *o32)
{
    char fn[1024];
    _snprintf(fn, 1024, "%s\\%s", g_outputdirectory, filename);
    FILE *f= fopen(fn, "w+b");
    if (f==NULL)
    {
        perror(fn);
        return;
    }

    WriteDummyMZHeader(f);

    DWORD dwE32Ofs= ftell(f);
    WriteE32Header(f, e32, t, o32);

    vector<DWORD> o32ofslist;
    vector<DWORD> dataofslist;
    vector<DWORD> datalenlist;

    memset(g_segmentNameUsage, 0, sizeof(g_segmentNameUsage));
    int i;
    for (i=0 ; i<e32->e32_objcnt ; i++)
    {
        o32ofslist.push_back(ftell(f));
        WriteO32Header(f, e32, &o32[i]);
    }

    WriteAlignment(f, 0x200);

    DWORD dwHeaderSize= ftell(f);

    for (i=0 ; i<e32->e32_objcnt ; i++)
    {
        dataofslist.push_back(ftell(f));
        DWORD datalen= WriteUncompressedData(f, o32[i].o32_dataptr, min(o32[i].o32_vsize, o32[i].o32_psize), o32[i].o32_flags&IMAGE_SCN_COMPRESSED, o32[i].o32_vsize);
        datalenlist.push_back(datalen);

        WriteAlignment(f, 0x200);
    }
    DWORD dwTotalFileSize= ftell(f);

    // fix rawdatalen + dataoffsets in segment list
    for (i=0 ; i<e32->e32_objcnt ; i++)
    {
        fseek(f, o32ofslist[i]+16, SEEK_SET);
        fwrite(&datalenlist[i], 1, sizeof(DWORD), f);   // ofs to o32_psize
        fwrite(&dataofslist[i], 1, sizeof(DWORD), f);   // ofs to o32_dataptr
    }

    fseek(f, dwE32Ofs+0x54, SEEK_SET);  // ofs to e32_hdrsize
    fwrite(&dwHeaderSize, 1, sizeof(DWORD), f);

    fseek(f, dwTotalFileSize, SEEK_SET);
    fclose(f);

    //todo: set fileattributes + datetime.
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
void DumpXIPChainEntry(int xipnr, XIPCHAIN_ENTRY *xip)
{
    g_regions.MarkRegion(g_mem.GetOfs(xip), sizeof(XIPCHAIN_ENTRY), "xip%d : %s", xipnr, xip->szName);
    g_regions.MarkRegion((DWORD)xip->pvAddr, 0, "start xip%d : %s", xipnr, xip->szName);

    if (g_verbose)
        g_regions.MarkRegion((DWORD)xip->pvAddr+xip->dwLength, 0, "end xip%d : %s", xipnr, xip->szName);
}

void DumpXIPChain(DWORD dwXipOffset)
{
    XIPCHAIN_INFO *xipchain= (XIPCHAIN_INFO *)g_mem.GetPtr(dwXipOffset);
    if (xipchain==NULL)
        return;

    if (xipchain->cXIPs > MAX_ROM)
    {
        printf("ERROR - invalid xipchain\n");
        return;
    }
    g_regions.MarkRegion(dwXipOffset, sizeof(DWORD), "xipchain head");

    XIPCHAIN_ENTRY *xip= &xipchain->xipEntryStart;

    for (DWORD i=0 ; i<xipchain->cXIPs ; ++i)
    {
        DumpXIPChainEntry(i, &xip[i]);
    }
}

void DumpExtensions(DWORD dwPidOffset)
{
    ROMPID *pid= (ROMPID *)g_mem.GetPtr(dwPidOffset);

    if (pid==NULL)
        return;
    // first is inside nk.exe
    pid= (ROMPID*)g_mem.GetPtr(dwPidOffset=(DWORD)pid->pNextExt);
    while (pid) {
        g_regions.MarkRegion(dwPidOffset, sizeof(ROMPID), "rom extension entry %s", pid->s.name);
        g_regions.MarkRegion((DWORD)pid->s.pdata, pid->s.length, "rom extension data %s", pid->s.name);

        pid= (ROMPID*)g_mem.GetPtr(dwPidOffset=(DWORD)pid->pNextExt);
    }
}
void DumpModuleTOCentry(int modnr, DWORD ofs)
{
    TOCentry *t= (TOCentry *)g_mem.GetPtr(ofs);
    if (t==NULL)
    {
        printf("invalid modtoc ofs %08lx\n", ofs);
        return;
    }

    char *filename= (char *)g_mem.GetPtr((DWORD)t->lpszFileName);
    if (filename==NULL)
        return;

    g_regions.MarkRegion(ofs, sizeof(TOCentry), "modent %3d %08lx %08lx%08lx %8d %08lx %s",
            modnr, t->dwFileAttributes, t->ftTime.dwHighDateTime, t->ftTime.dwLowDateTime, t->nFileSize, t->ulLoadOffset, filename);

    g_regions.MarkRegion((DWORD)t->lpszFileName, strlen(filename)+1, "modname %s", filename);

    e32_rom *e32= (e32_rom *)g_mem.GetPtr((DWORD)t->ulE32Offset);
    if (e32==NULL)
        return;
    MemRegion &m=  g_regions.MarkRegion((DWORD)t->ulE32Offset, sizeof(e32_rom), "e32 struct %d objs, img=%04x entrypt=%08lx base=%08lx v%d.%d tp%d %s", 
            e32->e32_objcnt, e32->e32_imageflags, e32->e32_entryrva, e32->e32_vbase, e32->e32_subsysmajor, e32->e32_subsysminor, e32->e32_subsys, filename);

    o32_rom *o32= (o32_rom *)g_mem.GetPtr((DWORD)t->ulO32Offset);
    if (o32==NULL)
        return;
    if (g_verbose) {
        *m.description += dworddumpasstring(t->ulE32Offset, t->ulE32Offset+sizeof(e32_rom));
    }

    m= g_regions.MarkRegion((DWORD)t->ulO32Offset, e32->e32_objcnt*sizeof(o32_rom), "o32 struct %s", filename);
    for (int i= 0 ; i<e32->e32_objcnt ; ++i)
    {
        m= g_regions.MarkRegion(o32[i].o32_dataptr, min(o32[i].o32_vsize, o32[i].o32_psize), 
                "o32 region_%d rva=%08lx vsize=%08lx real=%08lx psize=%08lx f=%08lx for %s", i, o32[i].o32_rva, o32[i].o32_vsize, o32[i].o32_realaddr, o32[i].o32_psize, o32[i].o32_flags, filename);

//        if (g_outputdirectory)
//            UncompressAndWrite(m.start, m.end, filename, i, o32[i].o32_flags&IMAGE_SCN_COMPRESSED, o32[i].o32_vsize, o32[i].o32_realaddr);
    }

    if (g_outputdirectory)
        CreateOriginalFile(t, filename, e32, o32);
}
void DumpFileTOCentry(int filenr, DWORD ofs)
{
    FILESentry *t= (FILESentry *)g_mem.GetPtr(ofs);
    if (t==NULL)
    {
        printf("invalid filetoc ofs %08lx\n", ofs);
        return;
    }

    char *filename= (char *)g_mem.GetPtr((DWORD)t->lpszFileName);
    if (filename==NULL)
        return;

    g_regions.MarkRegion(ofs, sizeof(FILESentry), "filent %3d %08lx %08lx%08lx %8d %8d %08lx %s",
            filenr, t->dwFileAttributes, t->ftTime.dwHighDateTime, t->ftTime.dwLowDateTime, t->nRealFileSize, t->nCompFileSize, t->ulLoadOffset, filename);
    g_regions.MarkRegion((DWORD)t->lpszFileName, strlen(filename)+1, "filename %s", filename);
    MemRegion &m= g_regions.MarkRegion((DWORD)t->ulLoadOffset, t->nCompFileSize, "filedata %s", filename);


    if (g_outputdirectory) {
        UncompressAndWrite(m.start, m.end, filename, -1, t->nCompFileSize!=t->nRealFileSize, t->nRealFileSize, t->ulLoadOffset);
    }
}
void DumpRomHdr(int romnr, DWORD ofs)
{
    ROMHDR *r= (ROMHDR *)g_mem.GetPtr(ofs);
    if (r==NULL)
    {
        printf("invalid romhdr ofs %08lx\n", ofs);
        return;
    }

// r->ulRAMFree r->ulFSRamPercent, 
    MemRegion &m= g_regions.MarkRegion(ofs, sizeof(ROMHDR), 
            "rom_%02d header: dlls=%08lx-%08lx phys=%08lx-%08lx, %d modules, %d files, %d copyentries ext=%08lx  ram=%08lx-%08lx cputype=%08lx", 
            romnr, r->dllfirst, r->dlllast, r->physfirst, r->physlast,
            r->nummods, r->numfiles, r->ulCopyEntries, r->pExtensions,
            r->ulRAMStart, r->ulRAMEnd, r->usCPUType);

    if (g_verbose) {
        *m.description += dworddumpasstring(ofs, ofs+sizeof(ROMHDR));
    }
    g_regions.MarkRegion(r->physfirst, 0, "rom_%02d start", romnr);
    g_regions.MarkRegion(r->physlast, 0, "rom_%02d end", romnr);

    if (r->pExtensions)
        DumpExtensions((DWORD)r->pExtensions);

	DWORD i;
	TOCentry *tm= (TOCentry *)&r[1];
	for (i=0 ; i<r->nummods; i++)
	{
		DumpModuleTOCentry(i, g_mem.GetOfs(&tm[i]));
	}
	FILESentry *tf= (FILESentry *)&tm[r->nummods];
	for (i=0 ; i<r->numfiles; i++)
	{
		DumpFileTOCentry(i, g_mem.GetOfs(&tf[i]));
	}

    if (r->ulCopyEntries) {
        COPYentry *cp= (COPYentry *)g_mem.GetPtr(r->ulCopyOffset);
        if (cp==NULL)
            return;
        MemRegion &m= g_regions.MarkRegion(r->ulCopyOffset, sizeof(COPYentry)*r->ulCopyEntries, "rom_%02d copy to ram: ", romnr);
        for (DWORD i=0 ; i<r->ulCopyEntries ; ++i)
        {
            char buf[64];
            _snprintf(buf, 64, " %08lxL%06lx -> %08lxL%06lx", cp->ulSource, cp->ulCopyLen, cp->ulDest, cp->ulDestLen);
            *m.description += buf;
        }
    }
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
typedef map<DWORD,DWORD> MapDwordDword;

    struct ScoreCmp {
		ScoreCmp(const MapDwordDword& map) : m_map(map) {}
        bool operator()(DWORD a, DWORD b) {
            return m_map[a] > m_map[b];
        }
		MapDwordDword m_map;
    };
DWORD FindXipRegion()
{
    // find all occurrences of 'RSA1'
    // '0x48' = offset in struct + xip header
    vector<DWORD> pos;
    for (MemoryMapIterator i(g_mem.begin()) ; i!=g_mem.end() ; i+=4)
    {
        if (i.GetDword()==0x31415352)
            pos.push_back(i.m_ofs-0x48);
    }
    // look for sequence of 'RSA1'
    MapDwordDword posscore;
    DWORD start=0;
    for(vector<DWORD>::iterator i= pos.begin() ; i!=pos.end() ; ++i)
    {
        if (!start || *i != start+0x290) {
            start= *i;
            posscore[start]++;
        }
        else {
            posscore[start]++;
        }
    }
	
    sort(pos.begin(), pos.end(), ScoreCmp(posscore));
    // try in descending nr of hits
    for (MapDwordDword::iterator i= posscore.begin() ; i!=posscore.end() ; ++i)
    {
        if ((*i).first % 0x1000)
            continue;
        DWORD nxips= g_mem.GetDword((*i).first);

        if (nxips>= (*i).second)
            return (*i).first;
    }
    return 0;
}

#define IMGOFSINCREMENT 0x1000
void ScanRom()
{
	set<DWORD> romhdrs;
    // future: fix iterating over memblocks, now it does not handle 'holes' in the memory range very well.
    int romnr= 0;
    for (DWORD romofs= (g_mem.FirstAddress()+IMGOFSINCREMENT-1)&~(IMGOFSINCREMENT-1); romofs<g_mem.LastAddress(); romofs+=IMGOFSINCREMENT)
    {
        DWORD *rom= (DWORD*)g_mem.GetPtr(romofs);
        if (rom==NULL)
            continue;
		if (rom[ROM_SIGNATURE_OFFSET/sizeof(DWORD)]==ROM_SIGNATURE)
        {
            g_regions.MarkRegion(g_mem.GetOfs(rom), 4, "romsection id=%08lx", rom[0]);
            g_regions.MarkRegion(g_mem.GetOfs(&rom[16]), 8, "'ECEC' -> %08lx", rom[17]);

			if (romhdrs.find(rom[17])==romhdrs.end())
			{
				DumpRomHdr(romnr++, rom[17]);

				romhdrs.insert(rom[17]);	// keep track of multiple pointers to same header.
			}
        }
	}
}

// parse string of format: <ofs>:<len>:<desc>
//                     or: <start>-<end>:<desc>
bool ParseRegionSpec(const string& spec, DWORD& start, DWORD& length, string& description)
{
    string::size_type pos_colon= spec.find(':');
    string::size_type pos_2ndcolon= spec.find(':', pos_colon+1);
    string::size_type pos_dash= spec.find('-');

    if (pos_colon==spec.npos || (pos_2ndcolon==spec.npos && pos_dash==spec.npos))
        return false;

    if (pos_dash==spec.npos)  // it is <ofs>:<len>:<desc>
    {
        start= strtoul(spec.substr(0, pos_colon).c_str(), 0, 0);
        length= strtoul(spec.substr(pos_colon+1, pos_2ndcolon-pos_colon-1).c_str(), 0, 0);
        description= spec.substr(pos_2ndcolon+1);
        return true;
    }
    else if (pos_dash < pos_colon)   // it is <ofs>-<end>:<desc>
    {
        start= strtoul(spec.substr(0, pos_dash).c_str(), 0, 0);
        DWORD end= strtoul(spec.substr(pos_dash+1, pos_colon-pos_dash-1).c_str(), 0, 0);
        length= end-start;
        description= spec.substr(pos_colon+1);
        return true;
    }
    else
        return false;
}

struct B000FFHeader {
	char signature[7];
	DWORD imgstart;
	DWORD imglength;

	DWORD blockstart;
	DWORD blocklength;
	DWORD blockchecksum;
	BYTE data[1];
};
DWORD GetFileSize(FILE *f)
{
	fseek(f, 0, SEEK_END);
	return ftell(f);
}

typedef enum { FT_B000FF, FT_NBF, FT_BIN } FileType;

bool isNBFHeader(char *hdr)
{
	return 	(hdr[10]=='-' && hdr[15]=='-' && hdr[19]=='-');
}
bool DetermineFileType(FILE *f, DWORD& start, DWORD& length, FileType& type)
{
	BYTE buf[32];
	fseek(f, 0, SEEK_SET);
	if (1!=fread(buf, 32, 1, f))
	{
		perror("fread");
		return false;
	}
	fseek(f, 0, SEEK_END);
	DWORD filesize= ftell(f);

	if (strnicmp((char*)buf, "B000FF", 6)==0)
	{
		B000FFHeader *hdr= (B000FFHeader *)buf;
		type= FT_B000FF;
	
		start= 7+5*4;
		length= hdr->blocklength;

		if (hdr->imglength!=hdr->blocklength || hdr->imgstart!=hdr->blockstart)
			return false;

		return true;
	}
	else if (isNBFHeader((char*)buf))
	{
		type= FT_NBF;
		start= 0x20;
		length= filesize-start;
		return true;
	}
	else {
		type= FT_BIN;
		start= 0;
		length= filesize;
		return true;
	}
}

bool ReadDword(FILE *f, DWORD offset, DWORD& dword)
{
	if (fseek(f, offset, SEEK_SET))
		return false;

	if (1!=fread(&dword, sizeof(DWORD), 1, f))
		return false;

	return true;
}

// this function tries to determine where in the file the image starts.
// it first checks the filetype, checks for ECEC -> knownvalue
// else scan file for 'ECEC', then returns ofs-0x40
bool DetermineImageOffset(FILE *f, DWORD& imagestart, DWORD& imagelength)
{
	FileType type;
	if (DetermineFileType(f, imagestart, imagelength, type))
	{
		DWORD sig;
		if (ReadDword(f, imagestart+0x40, sig)
			&& sig==ROM_SIGNATURE)
			return true;
	}
	// scan for ECEC

	fseek(f, 0, SEEK_SET);

	BYTE buf[65536+4];
	memset(buf, 0, 4);
	DWORD ofs=0;
	while(1)
	{
		DWORD nRead= fread(buf+4, 1, 65536, f);
		for (BYTE *p= buf ; p<buf+nRead+4 ; p++)
			if (*(DWORD*)p==ROM_SIGNATURE)
			{
				imagestart= ofs+(p-buf-4)-0x40;
				imagelength= GetFileSize(f)-imagestart;
				return true;
			}
		memcpy(buf, buf+nRead, 4);
		ofs += nRead;
	}
	return false;
}
// this function tries to find what offset the image is loaded at in ROM.
bool DetermineLoadOffset(FILE *f, DWORD imagestart, DWORD imagelength, DWORD& offset)
{
	int max= -1;
	DWORD maxbase= 0;

	map<DWORD, int> bases;

	bool res= false;
#define IMGOFSINCREMENT 0x1000
	// imgofs is scanning for 'ECEC' headers
	for (DWORD imgofs= 0 ; (imgofs + IMGOFSINCREMENT)<imagelength ; imgofs+=IMGOFSINCREMENT)
	{
		DWORD sig;
		if (!ReadDword(f, imagestart+imgofs+64, sig))
			goto err_exit;
		if (sig!=ROM_SIGNATURE)
			continue;

		DWORD romhdr;
		if (!ReadDword(f, imagestart+imgofs+68, romhdr))
			goto err_exit;
		// find imgbase, such that imgbase+imgofs== romhdr[8] = file[romhdr-imgbase+imagestart+8]
		for (DWORD imgbase=(romhdr+imagestart- imagelength)&~0xfff ; imgbase< romhdr+imagestart ; imgbase+=0x1000)
		{
			DWORD physfirst;
			if (!ReadDword(f, romhdr+imagestart-imgbase+8, physfirst))
				continue;
			if (physfirst==imgofs+imgbase)
			{
				printf("img %08lx : hdr=%08lx base=%08lx  commandlineoffset=%08lx\n", imgofs, romhdr, imgbase, imgbase-imagestart);
				bases[imgbase]++;
				if (bases[imgbase] > max)
				{
					max= bases[imgbase];
					maxbase= imgbase;
				}
			}
		}
	}
	if (max>0)
	{
		offset= maxbase-imagestart;
		res= true;
	}	
err_exit:
	return res;
}

void usage()
{
    printf("Usage: dumprom [options] imagefile [offset [imagefile offset ...]]\n");
    printf("   -d <dirpath>  - save found files/modules to this path\n");
    printf("   -v            - verbose : print alignment, struct contents\n");
    printf("   -q            - quiet : don't print anything\n");
    printf("   -u <ofs>L<len>:desc   - add user defined memory regions to complete image\n");
    printf("   -x <offset>   - process XIP chain at offset\n");
	printf("   -i <offset>   - specifiy image start offset\n");
	printf("   -3            - use wince3.x decompression [ default ]\n");
	printf("   -4            - use wince4.x decompression [ default ]\n");
}

typedef vector<string> stringlist;

#define HANDLEULOPTION(var, type) (argv[i][2] ? var= (type)strtoul(argv[i]+2, 0, 0) : i+1<argc ? var= (type)strtoul(argv[++i], 0, 0) : 0)
#define HANDLESTROPTION(var) (argv[i][2] ? var= argv[i]+2 : i+1<argc ? var= argv[++i] : 0)

int main( int argc, char *argv[])
{
    bool bQuiet= false;
    char *imagefilename=NULL;
    stringlist userregions;
    DWORD dwXipOffset= 0;
	char *userregionstr= NULL;

	FILE *f= NULL;

	bool bHaveImageStart= false;
	DWORD imagestart=0, imagelength=0;
	FileType type;

    int argsfound=0;
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-')
            switch(argv[i][1])
            {
                case 'd':
					HANDLESTROPTION(g_outputdirectory);
                    break;
                case 'v':
                    g_verbose++;
                    break;
                case 'q':
                    bQuiet= true;
                    break;
                case 'u':
					if (HANDLESTROPTION(userregionstr))
						userregions.push_back(userregionstr);
                    break;
                case 'x':
					HANDLEULOPTION(dwXipOffset, DWORD);
                    break;
				case 'i':
					if (HANDLEULOPTION(imagestart, DWORD))
						bHaveImageStart= true;
					break;
				case '4':
					cedecompress= CEDecompressROM;
					break;
				case '3':
					cedecompress= CEDecompress;
					break;
                default:
                    usage();
                    return 1;
            }
        else if (argsfound&1) {
            DWORD loadoffset= strtoul(argv[i],0,0);
            if (!g_mem.LoadFile(loadoffset, imagefilename, 0, 0))
                return 1;
            argsfound++;
        }
        else {
            imagefilename= argv[i];
			if (f) fclose(f);
			f= fopen(imagefilename, "rb");
			if (f==NULL)
			{
				perror(imagefilename);
				return 1;
			}
            argsfound++;
        }
    }
    if (argsfound&1) {
		
		if (bHaveImageStart)
			imagelength= GetFileSize(f);
		if (!bHaveImageStart && !DetermineImageOffset(f, imagestart, imagelength))
		{
			printf("unable to determine image start offset\n");
			return 1;
		}

		DWORD loadoffset;
		if (!DetermineLoadOffset(f, imagestart, imagelength, loadoffset))
		{
			printf("unable to determine loading offset for %s\n", imagefilename);
			return 1;
		}
        if (!g_mem.LoadFile(loadoffset, imagefilename, 0, 0))
            return 1;
    }
    if (f) fclose(f);
    if (argsfound==0) {
        usage();
        return 1;
    }

    ScanRom();

//  ... not working yet.
//    if (dwXipOffset==0)
//		dwXipOffset= FindXipRegion();
	if (dwXipOffset)
        DumpXIPChain(dwXipOffset);

    for (stringlist::iterator i= userregions.begin() ; i!= userregions.end() ; ++i)
    {
        DWORD start, length;
        string description;
        if (ParseRegionSpec(*i, start, length, description))
            g_regions.MarkRegion(start, length, "%s", description.c_str());
    }

    if (!bQuiet)
        g_regions.DumpMemoryMap();
}
