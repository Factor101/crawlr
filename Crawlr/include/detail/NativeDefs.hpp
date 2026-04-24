#pragma once
#ifndef NATIVE_H
#define NATIVE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif  // !WIN32_LEAN_AND_MEAN

#include <cstdint>
#include <ntdef.h>
#include <windef.h>

namespace CrawlrNative
{
typedef unsigned char UBYTE;
typedef void* PVOID;
typedef union _UNWIND_CODE
{
    struct
    {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

// unwind opcodes: https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#unwind-operation-code
// and https://github.com/reactos/reactos/blob/3bd9ddca94bda829b3977918a1be0a92a8a610f6/sdk/lib/rtl/amd64/unwind.c#L537
typedef enum _UNWIND_OP_CODES
{
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;


typedef struct _UNWIND_INFO
{
    UCHAR Version : 3;
    UCHAR Flags   : 5;
    UCHAR SizeOfPrologue;
    UCHAR CountOfUnwindCodes;
    UCHAR FrameRegister       : 4;
    UCHAR FrameRegisterOffset : 4;
    UNWIND_CODE UnwindCode[1];
    // UNWIND_CODE MoreUnwindCode[((CountOfUnwindCodes + 1) & ~1) - 1];
    union
    {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };

    OPTIONAL ULONG ExceptionData[];
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _EXCEPTION_INFO
{
    UINT64 hModule;
    UINT64 pExceptionDirectory;
    DWORD dwRuntimeFunctionCount;
} EXCEPTION_INFO, *PEXCEPTION_INFO;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    DWORD EndAddress;
    union
    {
        DWORD UnwinInfoAddress;
        DWORD UnwindData;
    } DUMMYUNIONNAME;

} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY,
    *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _PS_ATTRIBUTE
{
    ULONG Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;


typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,  // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit               : 1;
                    UCHAR DetectManifest                  : 1;
                    UCHAR IFEOSkipDebugger                : 1;
                    UCHAR IFEODoNotPropagateKeyState      : 1;
                    UCHAR SpareBits1                      : 4;
                    UCHAR SpareBits2                      : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess      : 1;
                    UCHAR AddressSpaceOverride  : 1;
                    UCHAR DevOverrideEnabled    : 1;  // from Image File Execution Options
                    UCHAR ManifestDetected      : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1            : 3;
                    UCHAR SpareBits2            : 8;
                    USHORT SpareBits3           : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;


#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s)                  \
    {                                                              \
        (p)->Length                   = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory            = r;                         \
        (p)->Attributes               = a;                         \
        (p)->ObjectName               = n;                         \
        (p)->SecurityDescriptor       = s;                         \
        (p)->SecurityQualityOfService = NULL;                      \
    }
#endif

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA
{
    uint32_t Length;
    uint8_t Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    union
    {
        LIST_ENTRY InInitializationOrderModuleList;
        LIST_ENTRY InProgressLinks;
    };
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
    bool InheritedAddressSpace;
    bool ReadImageFileExecOptions;
    bool BeingDebugged;
    bool ImageUsesLargePages          : 1;
    bool IsProtectedProcess           : 1;
    bool IsImageDynamicallyRelocated  : 1;
    bool SkipPatchingUser32Forwarders : 1;
    bool IsPackagedProcess            : 1;
    bool IsAppContainer               : 1;
    bool IsProtectedProcessLight      : 1;
    bool IsLongPathAwareProcess       : 1;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    bool ProcessInJob               : 1;
    bool ProcessInitializing        : 1;
    bool ProcessUsingVEH            : 1;
    bool ProcessUsingVCH            : 1;
    bool ProcessUsingFTH            : 1;
    bool ProcessPreviouslyThrottled : 1;
    bool ProcessCurrentlyThrottled  : 1;
    bool ProcessImagesHotPatched    : 1;
    uint32_t ReservedBits0          : 24;
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    PVOID ApiSetMap;
    uint32_t TlsExpansionCounter;
    PVOID TlsBitmap;
    uint32_t TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
    uint64_t CriticalSectionTimeout;
    size_t HeapSegmentReserve;
    size_t HeapSegmentCommit;
    size_t HeapDeCommitTotalFreeThreshold;
    size_t HeapDeCommitFreeBlockThreshold;
    uint32_t NumberOfHeaps;
    uint32_t MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    uint32_t GdiDCAttributeList;
    PVOID LoaderLock;
    uint32_t OSMajorVersion;
    uint32_t OSMinorVersion;
    uint16_t OSBuildNumber;
    uint16_t OSCSDVersion;
    uint32_t OSPlatformId;
    uint32_t ImageSubsystem;
    uint32_t ImageSubsystemMajorVersion;
    uint32_t ImageSubsystemMinorVersion;
    uint32_t* ActiveProcessAffinityMask;
    uint32_t GdiHandleBuffer[60];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    uint32_t TlsExpansionBitmapBits[32];
    uint32_t SessionId;
} PEB, *PPEB;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#endif  // NATIVE_H
}
