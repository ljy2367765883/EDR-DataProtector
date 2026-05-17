#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

#define DPUSB_DOS_NAME L"\\\\.\\DataProtectorUsbCrypt"
#define DPUSB_SERVICE_NAME L"DataProtectorUsbCrypt"
#define DPUSB_ALGORITHM_RC4 1
#define DPUSB_MAX_DEVICE_ID_CHARS 260
#define DPUSB_MAX_KEY_BYTES 64
#define DPUSB_MIN_TOOL_BYTES (5ull * 1024ull * 1024ull)
#define DPUSB_IOCTL_INDEX 0x900
#define IOCTL_DPUSB_QUERY_STATUS CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DPUSB_OPEN_SESSION CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DPUSB_CLOSE_SESSION CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 2, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _DPUSB_OPEN_SESSION {
    ULONG Version;
    ULONG Algorithm;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    ULONG KeyLength;
    UCHAR Key[DPUSB_MAX_KEY_BYTES];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_OPEN_SESSION;

typedef struct _DPUSB_STATUS {
    ULONG Version;
    BOOLEAN SessionOpen;
    ULONG Algorithm;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_STATUS;

static void PrintUsage(void)
{
    wprintf(L"DataProtector USB Crypt Tool\n");
    wprintf(L"\n");
    wprintf(L"Commands:\n");
    wprintf(L"  status\n");
    wprintf(L"  install-driver <DataProtectorUsbCrypt.sys>\n");
    wprintf(L"  start-driver\n");
    wprintf(L"  stop-driver\n");
    wprintf(L"  unlock <device-id> <hex-key> [data-offset-bytes] [data-length-bytes]\n");
    wprintf(L"  lock\n");
    wprintf(L"  init-plan <drive-letter> <hex-key>\n");
    wprintf(L"\n");
    wprintf(L"Notes:\n");
    wprintf(L"  init-plan only prints the destructive steps required for controlled provisioning.\n");
    wprintf(L"  Disk formatting and partition shrinking must be wired to an explicit production workflow.\n");
}

static int HexNibble(wchar_t ch)
{
    if (ch >= L'0' && ch <= L'9') return ch - L'0';
    if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
    if (ch >= L'A' && ch <= L'F') return ch - L'A' + 10;
    return -1;
}

static BOOL ParseHexKey(const wchar_t *text, BYTE *key, DWORD *keyLength)
{
    size_t length;
    DWORD index;

    if (text == NULL || key == NULL || keyLength == NULL) {
        return FALSE;
    }

    length = wcslen(text);
    if (length == 0 || (length % 2) != 0 || length / 2 > DPUSB_MAX_KEY_BYTES) {
        return FALSE;
    }

    for (index = 0; index < length / 2; index++) {
        int hi = HexNibble(text[index * 2]);
        int lo = HexNibble(text[index * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return FALSE;
        }

        key[index] = (BYTE)((hi << 4) | lo);
    }

    *keyLength = (DWORD)(length / 2);
    return TRUE;
}

static ULONGLONG ParseU64(const wchar_t *text, ULONGLONG fallback)
{
    wchar_t *end = NULL;
    ULONGLONG value;

    if (text == NULL || *text == L'\0') {
        return fallback;
    }

    value = _wcstoui64(text, &end, 10);
    return end != NULL && *end == L'\0' ? value : fallback;
}

static HANDLE OpenControlDevice(DWORD access)
{
    return CreateFileW(DPUSB_DOS_NAME,
                       access,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
}

static int PrintLastError(const wchar_t *action)
{
    DWORD error = GetLastError();
    fwprintf(stderr, L"%s failed: %lu\n", action, error);
    return 1;
}

static int QueryStatus(void)
{
    HANDLE device;
    DPUSB_STATUS status;
    DWORD returned = 0;

    device = OpenControlDevice(GENERIC_READ);
    if (device == INVALID_HANDLE_VALUE) {
        return PrintLastError(L"Open control device");
    }

    ZeroMemory(&status, sizeof(status));
    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_QUERY_STATUS,
                         NULL,
                         0,
                         &status,
                         sizeof(status),
                         &returned,
                         NULL)) {
        CloseHandle(device);
        return PrintLastError(L"Query status");
    }

    wprintf(L"session=%s algorithm=%lu toolArea=%I64u dataOffset=%I64u dataLength=%I64u device=%s\n",
            status.SessionOpen ? L"open" : L"closed",
            status.Algorithm,
            status.ToolAreaBytes,
            status.DataOffsetBytes,
            status.DataLengthBytes,
            status.DeviceId);

    CloseHandle(device);
    return 0;
}

static int Unlock(int argc, wchar_t **argv)
{
    HANDLE device;
    DPUSB_OPEN_SESSION request;
    DWORD returned = 0;
    DWORD keyLength = 0;
    ULONGLONG offset = DPUSB_MIN_TOOL_BYTES;
    ULONGLONG length = 0;

    if (argc < 4) {
        PrintUsage();
        return 2;
    }

    if (argc >= 5) {
        offset = ParseU64(argv[4], DPUSB_MIN_TOOL_BYTES);
    }

    if (argc >= 6) {
        length = ParseU64(argv[5], 0);
    }

    ZeroMemory(&request, sizeof(request));
    request.Version = 1;
    request.Algorithm = DPUSB_ALGORITHM_RC4;
    request.ToolAreaBytes = DPUSB_MIN_TOOL_BYTES;
    request.DataOffsetBytes = offset;
    request.DataLengthBytes = length;
    wcsncpy_s(request.DeviceId,
              sizeof(request.DeviceId) / sizeof(request.DeviceId[0]),
              argv[2],
              _TRUNCATE);

    if (!ParseHexKey(argv[3], request.Key, &keyLength)) {
        fwprintf(stderr, L"Invalid RC4 key. Provide 2-128 hex characters.\n");
        return 2;
    }

    request.KeyLength = keyLength;

    device = OpenControlDevice(GENERIC_READ | GENERIC_WRITE);
    if (device == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(&request, sizeof(request));
        return PrintLastError(L"Open control device");
    }

    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_OPEN_SESSION,
                         &request,
                         sizeof(request),
                         NULL,
                         0,
                         &returned,
                         NULL)) {
        CloseHandle(device);
        SecureZeroMemory(&request, sizeof(request));
        return PrintLastError(L"Open session");
    }

    SecureZeroMemory(&request, sizeof(request));
    CloseHandle(device);
    wprintf(L"USB crypt session opened.\n");
    return 0;
}

static int Lock(void)
{
    HANDLE device;
    DWORD returned = 0;

    device = OpenControlDevice(GENERIC_READ | GENERIC_WRITE);
    if (device == INVALID_HANDLE_VALUE) {
        return PrintLastError(L"Open control device");
    }

    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_CLOSE_SESSION,
                         NULL,
                         0,
                         NULL,
                         0,
                         &returned,
                         NULL)) {
        CloseHandle(device);
        return PrintLastError(L"Close session");
    }

    CloseHandle(device);
    wprintf(L"USB crypt session closed.\n");
    return 0;
}

static int InstallDriver(const wchar_t *path)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    wchar_t fullPath[MAX_PATH];

    if (path == NULL || !GetFullPathNameW(path, sizeof(fullPath) / sizeof(fullPath[0]), fullPath, NULL)) {
        return PrintLastError(L"Resolve driver path");
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (scm == NULL) {
        return PrintLastError(L"Open service manager");
    }

    service = CreateServiceW(scm,
                             DPUSB_SERVICE_NAME,
                             DPUSB_SERVICE_NAME,
                             SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS,
                             SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START,
                             SERVICE_ERROR_NORMAL,
                             fullPath,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
    if (service == NULL && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(scm,
                               DPUSB_SERVICE_NAME,
                               SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
        if (service != NULL) {
            ChangeServiceConfigW(service,
                                 SERVICE_KERNEL_DRIVER,
                                 SERVICE_DEMAND_START,
                                 SERVICE_ERROR_NORMAL,
                                 fullPath,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);
        }
    }

    if (service == NULL) {
        CloseServiceHandle(scm);
        return PrintLastError(L"Create service");
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    wprintf(L"Driver service installed: %s\n", fullPath);
    return 0;
}

static int StartStopDriver(BOOL start)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS status;
    BOOL ok;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        return PrintLastError(L"Open service manager");
    }

    service = OpenServiceW(scm, DPUSB_SERVICE_NAME, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service == NULL) {
        CloseServiceHandle(scm);
        return PrintLastError(L"Open service");
    }

    if (start) {
        ok = StartServiceW(service, 0, NULL);
        if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
            ok = TRUE;
        }
    } else {
        ok = ControlService(service, SERVICE_CONTROL_STOP, &status);
        if (!ok && GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
            ok = TRUE;
        }
    }

    if (!ok) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return PrintLastError(start ? L"Start service" : L"Stop service");
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    wprintf(L"Driver %s.\n", start ? L"started" : L"stopped");
    return 0;
}

static int InitPlan(int argc, wchar_t **argv)
{
    BYTE key[DPUSB_MAX_KEY_BYTES];
    DWORD keyLength;

    if (argc < 4) {
        PrintUsage();
        return 2;
    }

    if (!ParseHexKey(argv[3], key, &keyLength)) {
        fwprintf(stderr, L"Invalid RC4 key. Provide 2-128 hex characters.\n");
        return 2;
    }

    SecureZeroMemory(key, sizeof(key));

    wprintf(L"Provisioning plan for %s\n", argv[2]);
    wprintf(L"  1. Verify hardware id against central authorization policy.\n");
    wprintf(L"  2. Confirm destructive initialization with the logged-in operator.\n");
    wprintf(L"  3. Clean and partition the disk with a %I64u-byte public tool area.\n", DPUSB_MIN_TOOL_BYTES);
    wprintf(L"  4. Copy DataProtectorUsbTool.exe and signed driver package into the public area.\n");
    wprintf(L"  5. Create the protected NTFS region after byte offset %I64u.\n", DPUSB_MIN_TOOL_BYTES);
    wprintf(L"  6. Store only non-secret metadata in the public header; keys remain server/agent managed.\n");
    wprintf(L"  7. Unlock with: DataProtectorUsbTool.exe unlock <hardware-id> <hex-key>\n");
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    if (_wcsicmp(argv[1], L"status") == 0) return QueryStatus();
    if (_wcsicmp(argv[1], L"lock") == 0) return Lock();
    if (_wcsicmp(argv[1], L"unlock") == 0) return Unlock(argc, argv);
    if (_wcsicmp(argv[1], L"install-driver") == 0) {
        if (argc < 3) {
            PrintUsage();
            return 2;
        }
        return InstallDriver(argv[2]);
    }
    if (_wcsicmp(argv[1], L"start-driver") == 0) return StartStopDriver(TRUE);
    if (_wcsicmp(argv[1], L"stop-driver") == 0) return StartStopDriver(FALSE);
    if (_wcsicmp(argv[1], L"init-plan") == 0) return InitPlan(argc, argv);

    PrintUsage();
    return 2;
}
