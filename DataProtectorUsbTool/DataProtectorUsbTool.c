#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <strsafe.h>
#include <wchar.h>

#define DPUSB_DOS_NAME L"\\\\.\\DataProtectorUsbCrypt"
#define DPUSB_NT_DEVICE_NAME L"\\Device\\DataProtectorUsbCrypt"
#define DPUSB_SERVICE_NAME L"DataProtectorUsbCrypt"
#define DPUSB_DRIVER_FILE_NAME L"DataProtectorUsbCrypt.sys"
#define DPUSB_APP_NAME L"DataProtector Secure USB"
#define DPUSB_PRIVATE_VOLUME_LABEL L"DPUSB-PRIVATE"
#define DPUSB_VIRTUAL_DEVICE_NUMBER 0x44505543UL
#define DPUSB_ALGORITHM_RC4 1
#define DPUSB_UNLOCK_METADATA_MAGIC 0x32535544UL
#define DPUSB_UNLOCK_METADATA_VERSION 2
#define DPUSB_UNLOCK_METADATA_BYTES 512
#define DPUSB_RAW_METADATA_RESERVED_BYTES (2ull * 1024ull * 1024ull)
#define DPUSB_UNLOCK_METADATA_OFFSET_BYTES (1024ull * 1024ull)
#define DPUSB_PUBLIC_TOOL_BYTES (5ull * 1024ull * 1024ull)
#define DPUSB_DATA_OFFSET_BYTES (DPUSB_RAW_METADATA_RESERVED_BYTES + DPUSB_PUBLIC_TOOL_BYTES)
#define DPUSB_UNLOCK_METADATA_DEVICE_ID_BYTES 128
#define DPUSB_UNLOCK_METADATA_PACKAGE_VERSION_BYTES 64
#define DPUSB_UNLOCK_METADATA_PACKAGE_SHA256_BYTES 64
#define DPUSB_UNLOCK_METADATA_RESERVED_BYTES 92
#define DPUSB_UNLOCK_KDF_BYTES (32 + DPUSB_MAX_KEY_BYTES)
#define DPUSB_MAX_DEVICE_ID_CHARS 260
#define DPUSB_MAX_KEY_BYTES 64
#define DPUSB_PASSWORD_SALT_BYTES 16
#define DPUSB_PASSWORD_VERIFIER_BYTES 32
#define DPUSB_MIN_TOOL_BYTES (5ull * 1024ull * 1024ull)
#define DPUSB_IOCTL_INDEX 0x900
#define IOCTL_DPUSB_QUERY_STATUS CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DPUSB_OPEN_SESSION CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DPUSB_CLOSE_SESSION CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 2, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DPUSB_MOUNT_DRIVE CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 3, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DPUSB_UNMOUNT_DRIVE CTL_CODE(FILE_DEVICE_DISK, DPUSB_IOCTL_INDEX + 4, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#ifndef IOCTL_VOLUME_UPDATE_PROPERTIES
#define IOCTL_VOLUME_UPDATE_PROPERTIES CTL_CODE(IOCTL_VOLUME_BASE, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#define DPUSB_ID_UNLOCK 1002
#define DPUSB_ID_LOCK 1003
#define DPUSB_ID_REFRESH 1004
#define DPUSB_ID_PLAN 1005
#define DPUSB_ID_SAFE_EJECT 1006
#define DPUSB_ID_TRAY_SHOW 1007
#define DPUSB_ID_TRAY_EXIT 1008
#define DPUSB_ID_PASSWORD 1102
#define DPUSB_ICON_ID 101
#define DPUSB_WM_APPEND_LOG (WM_APP + 1)
#define DPUSB_WM_UNLOCK_DONE (WM_APP + 2)
#define DPUSB_WM_TRAY (WM_APP + 3)
#define DPUSB_WM_SAFE_EJECT_DONE (WM_APP + 4)
#define DPUSB_TRAY_ICON_ID 1

typedef struct _DPUSB_OPEN_SESSION {
    ULONG Version;
    ULONG Algorithm;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    ULONG KeyLength;
    WCHAR PhysicalDrivePath[128];
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
    WCHAR PhysicalDrivePath[128];
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
} DPUSB_STATUS;

typedef struct _DPUSB_DRIVE_MOUNT {
    ULONG Version;
    WCHAR DriveLetter;
} DPUSB_DRIVE_MOUNT;

typedef struct _DPUSB_UNLOCK_MANIFEST {
    ULONG Magic;
    ULONG Version;
    ULONG MetadataBytes;
    ULONG Algorithm;
    ULONG KeyLength;
    ULONG KdfIterations;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
    BYTE PasswordSalt[DPUSB_PASSWORD_SALT_BYTES];
    BYTE PasswordVerifier[DPUSB_PASSWORD_VERIFIER_BYTES];
    BYTE WrappedKey[DPUSB_MAX_KEY_BYTES];
    CHAR DeviceId[DPUSB_UNLOCK_METADATA_DEVICE_ID_BYTES];
    CHAR PackageVersion[DPUSB_UNLOCK_METADATA_PACKAGE_VERSION_BYTES];
    CHAR PackageSha256[DPUSB_UNLOCK_METADATA_PACKAGE_SHA256_BYTES];
    BYTE Reserved[DPUSB_UNLOCK_METADATA_RESERVED_BYTES];
    ULONG Crc32;
} DPUSB_UNLOCK_MANIFEST;
C_ASSERT(sizeof(DPUSB_UNLOCK_MANIFEST) == DPUSB_UNLOCK_METADATA_BYTES);

typedef struct _DPUSB_UNLOCK_SECRET {
    WCHAR DeviceId[DPUSB_MAX_DEVICE_ID_CHARS];
    WCHAR PhysicalDrivePath[128];
    BYTE Key[DPUSB_MAX_KEY_BYTES];
    DWORD KeyLength;
    ULONGLONG ToolAreaBytes;
    ULONGLONG DataOffsetBytes;
    ULONGLONG DataLengthBytes;
} DPUSB_UNLOCK_SECRET;

typedef struct _DPUSB_PRIVATE_MOUNT {
    WCHAR Letter;
    WCHAR DosName[16];
    WCHAR Path[8];
} DPUSB_PRIVATE_MOUNT;

typedef struct _DPUSB_UNLOCK_WORK_ITEM {
    WCHAR Password[256];
} DPUSB_UNLOCK_WORK_ITEM;

typedef struct _DPUSB_UNLOCK_WORK_RESULT {
    BOOL Success;
    WCHAR DeployedDriverPath[MAX_PATH];
    WCHAR ServicePath[MAX_PATH + 8];
    WCHAR MountPath[8];
} DPUSB_UNLOCK_WORK_RESULT;

typedef struct _DPUSB_SAFE_EJECT_WORK_RESULT {
    BOOL Success;
    DWORD Error;
    WCHAR UsbRoot[MAX_PATH];
    WCHAR Message[512];
} DPUSB_SAFE_EJECT_WORK_RESULT;

typedef struct _DPUSB_UI_STATE {
    HWND Window;
    HWND PasswordEdit;
    HWND LogEdit;
    HWND RefreshButton;
    HWND UnlockButton;
    HWND LockButton;
    HWND SafeEjectButton;
    HWND PlanButton;
    HFONT TitleFont;
    HFONT HeaderFont;
    HFONT BodyFont;
    HFONT SmallFont;
    HBRUSH WindowBrush;
    HBRUSH CardBrush;
    HBRUSH EditBrush;
    COLORREF TextColor;
    COLORREF MutedColor;
    COLORREF AccentColor;
    COLORREF SuccessColor;
    COLORREF DangerColor;
    COLORREF BorderColor;
    COLORREF WindowColor;
    COLORREF CardColor;
    COLORREF EditColor;
    WCHAR DeployedDriverPath[MAX_PATH];
    WCHAR DriverPathText[MAX_PATH];
    WCHAR ServiceStateText[512];
    WCHAR SessionStateText[768];
    WCHAR DriverBadgeText[64];
    WCHAR SessionBadgeText[64];
    WCHAR MountPath[8];
    BOOL DriverReady;
    BOOL SessionOpen;
    BOOL OperationInProgress;
    BOOL TrayAdded;
    DWORD UiThreadId;
} DPUSB_UI_STATE;

typedef struct _DPUSB_UI_LAYOUT {
    RECT DriverCard;
    RECT SessionCard;
    RECT ControlCard;
    RECT LogCard;
    RECT PasswordEdit;
    RECT RefreshButton;
    RECT UnlockButton;
    RECT LockButton;
    RECT SafeEjectButton;
    RECT PlanButton;
} DPUSB_UI_LAYOUT;

typedef enum _DPUSB_SERVICE_PATH_MODE {
    DpUsbServicePathNativeDos = 0,
    DpUsbServicePathWin32 = 1
} DPUSB_SERVICE_PATH_MODE;

static DPUSB_UI_STATE g_Ui;
static BOOL g_UsbSourceRootSet = FALSE;
static WCHAR g_UsbSourceRoot[MAX_PATH];

static BOOL AutoPrepareDriver(wchar_t *deployedPath, DWORD deployedPathChars, wchar_t *servicePath, DWORD servicePathChars, DWORD *win32Error);
static BOOL OpenSessionWithSecret(const DPUSB_UNLOCK_SECRET *secret, DWORD *win32Error);
static BOOL UnlockSecretFromPassword(const wchar_t *password, DPUSB_UNLOCK_SECRET *secret, DWORD *win32Error);
static BOOL ReadUnlockManifest(DPUSB_UNLOCK_MANIFEST *manifest, DWORD *win32Error);
static BOOL IsProcessElevated(void);
static BOOL EnableProcessPrivilege(const wchar_t *privilegeName, DWORD *win32Error);
static BOOL MountPrivateWorkspace(DPUSB_PRIVATE_MOUNT *mount, DWORD *win32Error);
static BOOL EnsurePrivateWorkspaceFileSystem(const DPUSB_PRIVATE_MOUNT *mount, DWORD *win32Error);
static BOOL RequestKernelDriveMount(WCHAR letter, DWORD *win32Error);
static void RequestKernelDriveUnmount(WCHAR letter);
static void UnmountPrivateWorkspace(const DPUSB_PRIVATE_MOUNT *mount);
static void UnmountAllPrivateWorkspaces(void);
static DWORD Crc32Bytes(const BYTE *bytes, DWORD count);
static DWORD WINAPI UnlockWorkerThread(LPVOID parameter);
static DWORD WINAPI SafeEjectWorkerThread(LPVOID parameter);

static void PrintUsage(void)
{
    wprintf(L"DataProtector USB Crypt Tool\n");
    wprintf(L"\n");
    wprintf(L"Commands:\n");
    wprintf(L"  status\n");
    wprintf(L"  unlock-password <password>\n");
    wprintf(L"  lock\n");
    wprintf(L"\n");
    wprintf(L"Notes:\n");
    wprintf(L"  Running without arguments opens the USB unlock UI.\n");
    wprintf(L"  USB initialization, partitioning, formatting, and key assignment are performed by the endpoint agent from central web policy.\n");
    wprintf(L"  The tool only validates raw-disk USB metadata. A wrong password never loads the driver.\n");
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

static void FormatErrorMessage(DWORD error, wchar_t *buffer, DWORD bufferChars)
{
    DWORD written;

    if (buffer == NULL || bufferChars == 0) {
        return;
    }

    buffer[0] = L'\0';
    written = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL,
                             error,
                             0,
                             buffer,
                             bufferChars,
                             NULL);
    if (written == 0) {
        swprintf_s(buffer, bufferChars, L"Win32 error %lu", error);
        return;
    }

    while (written > 0 && (buffer[written - 1] == L'\r' || buffer[written - 1] == L'\n' || buffer[written - 1] == L' ')) {
        buffer[written - 1] = L'\0';
        written--;
    }
}

static BOOL IsExpectedDriverNotLoadedError(DWORD error)
{
    return error == ERROR_FILE_NOT_FOUND ||
           error == ERROR_PATH_NOT_FOUND ||
           error == ERROR_BAD_PATHNAME ||
           error == ERROR_INVALID_NAME;
}

static int PrintLastError(const wchar_t *action)
{
    DWORD error = GetLastError();
    fwprintf(stderr, L"%s failed: %lu\n", action, error);
    return 1;
}

static BOOL QueryStatusData(DPUSB_STATUS *status, DWORD *win32Error)
{
    HANDLE device;
    DWORD returned = 0;

    if (status == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    device = OpenControlDevice(GENERIC_READ);
    if (device == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    ZeroMemory(status, sizeof(*status));
    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_QUERY_STATUS,
                         NULL,
                         0,
                         status,
                         sizeof(*status),
                         &returned,
                         NULL)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseHandle(device);
        return FALSE;
    }

    CloseHandle(device);
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL CloseSessionData(DWORD *win32Error)
{
    HANDLE device;
    DWORD returned = 0;

    device = OpenControlDevice(GENERIC_READ | GENERIC_WRITE);
    if (device == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_CLOSE_SESSION,
                         NULL,
                         0,
                         NULL,
                         0,
                         &returned,
                         NULL)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseHandle(device);
        return FALSE;
    }

    CloseHandle(device);
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static int QueryStatus(void)
{
    DPUSB_STATUS status;

    if (!QueryStatusData(&status, NULL)) {
        return PrintLastError(L"Query status");
    }

    wprintf(L"session=%s algorithm=%lu toolArea=%I64u dataOffset=%I64u dataLength=%I64u device=%s\n",
            status.SessionOpen ? L"open" : L"closed",
            status.Algorithm,
            status.ToolAreaBytes,
            status.DataOffsetBytes,
            status.DataLengthBytes,
            status.DeviceId);

    return 0;
}

static int Lock(void)
{
    DWORD error = ERROR_SUCCESS;
    DPUSB_PRIVATE_MOUNT mount;

    ZeroMemory(&mount, sizeof(mount));
    UnmountAllPrivateWorkspaces();
    if (!CloseSessionData(&error)) {
        SetLastError(error);
        return PrintLastError(L"Close session");
    }

    wprintf(L"USB crypt session closed.\n");
    return 0;
}

static int UnlockPassword(int argc, wchar_t **argv)
{
    DPUSB_UNLOCK_SECRET secret;
    DPUSB_PRIVATE_MOUNT mount;
    wchar_t deployedPath[MAX_PATH];
    wchar_t servicePath[MAX_PATH + 8];
    DWORD error = ERROR_SUCCESS;

    if (argc < 3) {
        PrintUsage();
        return 2;
    }

    ZeroMemory(&secret, sizeof(secret));
    ZeroMemory(&mount, sizeof(mount));
    ZeroMemory(deployedPath, sizeof(deployedPath));
    ZeroMemory(servicePath, sizeof(servicePath));
    if (!UnlockSecretFromPassword(argv[2], &secret, &error)) {
        SetLastError(error);
        if (error == ERROR_ACCESS_DENIED) {
            fwprintf(stderr, L"Password verification failed. Driver was not loaded.\n");
            return 5;
        }
        return PrintLastError(L"Validate USB metadata");
    }

    if (!IsProcessElevated()) {
        SecureZeroMemory(&secret, sizeof(secret));
        fwprintf(stderr, L"Administrator privileges are required. The driver was not loaded.\n");
        return 5;
    }

    if (!AutoPrepareDriver(deployedPath,
                           sizeof(deployedPath) / sizeof(deployedPath[0]),
                           servicePath,
                           sizeof(servicePath) / sizeof(servicePath[0]),
                           &error)) {
        SecureZeroMemory(&secret, sizeof(secret));
        SetLastError(error);
        return PrintLastError(L"Prepare driver");
    }

    if (!OpenSessionWithSecret(&secret, &error)) {
        SecureZeroMemory(&secret, sizeof(secret));
        SetLastError(error);
        return PrintLastError(L"Open session");
    }

    if (!MountPrivateWorkspace(&mount, &error)) {
        CloseSessionData(NULL);
        SecureZeroMemory(&secret, sizeof(secret));
        SetLastError(error);
        return PrintLastError(L"Mount private workspace");
    }

    if (!EnsurePrivateWorkspaceFileSystem(&mount, &error)) {
        UnmountPrivateWorkspace(&mount);
        CloseSessionData(NULL);
        SecureZeroMemory(&secret, sizeof(secret));
        SetLastError(error);
        return PrintLastError(L"Initialize private workspace file system");
    }

    SecureZeroMemory(&secret, sizeof(secret));
    wprintf(L"USB crypt session opened from raw metadata. Private workspace: %s\n", mount.Path);
    return 0;
}

static void AppendLog(const wchar_t *format, ...)
{
    wchar_t line[1024];
    wchar_t stamped[1200];
    SYSTEMTIME now;
    va_list args;
    int textLength;
    wchar_t *posted;

    if (g_Ui.LogEdit == NULL) {
        return;
    }

    va_start(args, format);
    vswprintf_s(line, sizeof(line) / sizeof(line[0]), format, args);
    va_end(args);

    GetLocalTime(&now);
    swprintf_s(stamped,
               sizeof(stamped) / sizeof(stamped[0]),
               L"[%02u:%02u:%02u] %s\r\n",
               now.wHour,
               now.wMinute,
               now.wSecond,
               line);

    if (g_Ui.Window != NULL &&
        g_Ui.UiThreadId != 0 &&
        GetCurrentThreadId() != g_Ui.UiThreadId) {

        posted = (wchar_t *)LocalAlloc(LMEM_FIXED, (wcslen(stamped) + 1) * sizeof(wchar_t));
        if (posted != NULL) {
            wcscpy_s(posted, wcslen(stamped) + 1, stamped);
            if (PostMessageW(g_Ui.Window, DPUSB_WM_APPEND_LOG, 0, (LPARAM)posted)) {
                return;
            }
            LocalFree(posted);
        }
        return;
    }

    textLength = GetWindowTextLengthW(g_Ui.LogEdit);
    SendMessageW(g_Ui.LogEdit, EM_SETSEL, (WPARAM)textLength, (LPARAM)textLength);
    SendMessageW(g_Ui.LogEdit, EM_REPLACESEL, FALSE, (LPARAM)stamped);
}

static void AppendPostedLog(wchar_t *stamped)
{
    int textLength;

    if (stamped == NULL) {
        return;
    }

    if (g_Ui.LogEdit != NULL) {
        textLength = GetWindowTextLengthW(g_Ui.LogEdit);
        SendMessageW(g_Ui.LogEdit, EM_SETSEL, (WPARAM)textLength, (LPARAM)textLength);
        SendMessageW(g_Ui.LogEdit, EM_REPLACESEL, FALSE, (LPARAM)stamped);
    }

    LocalFree(stamped);
}

static void SetWindowTextSafe(HWND hwnd, const wchar_t *text)
{
    if (hwnd != NULL) {
        SetWindowTextW(hwnd, text != NULL ? text : L"");
    }
}

static void SetTextBuffer(wchar_t *buffer, DWORD bufferChars, const wchar_t *text)
{
    if (buffer == NULL || bufferChars == 0) {
        return;
    }

    wcsncpy_s(buffer, bufferChars, text != NULL ? text : L"", _TRUNCATE);
}

static BOOL IsProcessElevated(void)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD returned = 0;
    BOOL elevated = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return FALSE;
    }

    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
        elevated = elevation.TokenIsElevated != 0;
    }

    CloseHandle(token);
    return elevated;
}

static BOOL EnableProcessPrivilege(const wchar_t *privilegeName, DWORD *win32Error)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    DWORD error;

    if (privilegeName == NULL || privilegeName[0] == L'\0') {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        error = GetLastError();
        CloseHandle(token);
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    ZeroMemory(&privileges, sizeof(privileges));
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
        error = GetLastError();
        CloseHandle(token);
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    error = GetLastError();
    CloseHandle(token);
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL GetModuleDirectory(wchar_t *directory, DWORD directoryChars)
{
    DWORD length;
    wchar_t *slash;

    if (directory == NULL || directoryChars == 0) {
        return FALSE;
    }

    length = GetModuleFileNameW(NULL, directory, directoryChars);
    if (length == 0 || length >= directoryChars) {
        return FALSE;
    }

    slash = wcsrchr(directory, L'\\');
    if (slash == NULL) {
        return FALSE;
    }

    *slash = L'\0';
    return TRUE;
}

static BOOL GetModulePath(wchar_t *path, DWORD pathChars)
{
    DWORD length;

    if (path == NULL || pathChars == 0) {
        return FALSE;
    }

    length = GetModuleFileNameW(NULL, path, pathChars);
    return length != 0 && length < pathChars;
}

static BOOL CombinePath(wchar_t *output, DWORD outputChars, const wchar_t *left, const wchar_t *right)
{
    if (output == NULL || outputChars == 0 || left == NULL || right == NULL) {
        return FALSE;
    }

    return swprintf_s(output, outputChars, L"%s\\%s", left, right) > 0;
}

static BOOL GetModuleDriveRoot(wchar_t *root, DWORD rootChars)
{
    wchar_t moduleDir[MAX_PATH];
    wchar_t volumePath[MAX_PATH];

    if (root == NULL || rootChars == 0) {
        return FALSE;
    }

    if (!GetModuleDirectory(moduleDir, sizeof(moduleDir) / sizeof(moduleDir[0]))) {
        return FALSE;
    }

    if (!GetVolumePathNameW(moduleDir, volumePath, sizeof(volumePath) / sizeof(volumePath[0]))) {
        return FALSE;
    }

    wcsncpy_s(root, rootChars, volumePath, _TRUNCATE);
    return TRUE;
}

static BOOL RelaunchGuiFromLocalCacheIfNeeded(int showCommand)
{
    wchar_t modulePath[MAX_PATH];
    wchar_t moduleRoot[MAX_PATH];
    wchar_t targetDir[MAX_PATH];
    wchar_t targetPath[MAX_PATH];
    SHELLEXECUTEINFOW executeInfo;
    UINT driveType;

    if (!GetModulePath(modulePath, sizeof(modulePath) / sizeof(modulePath[0])) ||
        !GetModuleDriveRoot(moduleRoot, sizeof(moduleRoot) / sizeof(moduleRoot[0]))) {
        return FALSE;
    }

    driveType = GetDriveTypeW(moduleRoot);
    if (driveType != DRIVE_REMOVABLE && driveType != DRIVE_CDROM) {
        return FALSE;
    }

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, targetDir))) {
        return FALSE;
    }

    if (FAILED(StringCchCatW(targetDir, sizeof(targetDir) / sizeof(targetDir[0]), L"\\DataProtector\\UsbTool"))) {
        return FALSE;
    }

    if (SHCreateDirectoryExW(NULL, targetDir, NULL) != ERROR_SUCCESS &&
        GetFileAttributesW(targetDir) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(targetPath,
                                sizeof(targetPath) / sizeof(targetPath[0]),
                                L"%s\\DataProtectorUsbTool.exe",
                                targetDir))) {
        return FALSE;
    }

    if (!CopyFileW(modulePath, targetPath, FALSE)) {
        return FALSE;
    }

    ZeroMemory(&executeInfo, sizeof(executeInfo));
    executeInfo.cbSize = sizeof(executeInfo);
    executeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    executeInfo.lpFile = targetPath;
    executeInfo.nShow = showCommand;

    if (!ShellExecuteExW(&executeInfo)) {
        return FALSE;
    }

    if (executeInfo.hProcess != NULL) {
        CloseHandle(executeInfo.hProcess);
    }
    return TRUE;
}

static BOOL RootContainsUsbRuntime(const wchar_t *root)
{
    wchar_t candidate[MAX_PATH];

    if (root == NULL || root[0] == L'\0') {
        return FALSE;
    }

    if (swprintf_s(candidate,
                  sizeof(candidate) / sizeof(candidate[0]),
                  L"%sDataProtectorUsbRuntime\\driver\\%s",
                  root,
                  DPUSB_DRIVER_FILE_NAME) <= 0) {
        return FALSE;
    }

    return GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES;
}

static BOOL PhysicalPathForRoot(const wchar_t *root,
                                wchar_t *physicalPath,
                                DWORD physicalPathChars,
                                DWORD *win32Error)
{
    wchar_t volumePath[MAX_PATH];
    HANDLE volume;
    VOLUME_DISK_EXTENTS extents;
    DWORD returned = 0;

    if (root == NULL || root[0] == L'\0' || root[1] != L':' || physicalPath == NULL || physicalPathChars == 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (swprintf_s(volumePath,
                   sizeof(volumePath) / sizeof(volumePath[0]),
                   L"\\\\.\\%c:",
                   root[0]) <= 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INSUFFICIENT_BUFFER;
        }
        return FALSE;
    }

    volume = CreateFileW(volumePath,
                         0,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);
    if (volume == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    ZeroMemory(&extents, sizeof(extents));
    if (!DeviceIoControl(volume,
                         IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                         NULL,
                         0,
                         &extents,
                         sizeof(extents),
                         &returned,
                         NULL) ||
        extents.NumberOfDiskExtents < 1) {
        if (win32Error != NULL) {
            *win32Error = GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_INVALID_DATA;
        }
        CloseHandle(volume);
        return FALSE;
    }

    CloseHandle(volume);
    if (swprintf_s(physicalPath,
                   physicalPathChars,
                   L"\\\\.\\PhysicalDrive%lu",
                   extents.Extents[0].DiskNumber) <= 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INSUFFICIENT_BUFFER;
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL IsUsbBackedPhysicalDisk(const wchar_t *physicalPath)
{
    HANDLE disk;
    STORAGE_PROPERTY_QUERY query;
    BYTE buffer[1024];
    DWORD returned = 0;
    STORAGE_DEVICE_DESCRIPTOR *descriptor;

    if (physicalPath == NULL || physicalPath[0] == L'\0') {
        return FALSE;
    }

    disk = CreateFileW(physicalPath,
                       0,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
    if (disk == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    ZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    ZeroMemory(buffer, sizeof(buffer));
    if (!DeviceIoControl(disk,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         &query,
                         sizeof(query),
                         buffer,
                         sizeof(buffer),
                         &returned,
                         NULL)) {
        CloseHandle(disk);
        return FALSE;
    }

    CloseHandle(disk);
    if (returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return FALSE;
    }

    descriptor = (STORAGE_DEVICE_DESCRIPTOR *)buffer;
    return descriptor->BusType == BusTypeUsb || descriptor->RemovableMedia != FALSE;
}

static BOOL ReadManifestFromPhysicalPath(const wchar_t *physicalPath,
                                         DPUSB_UNLOCK_MANIFEST *manifest,
                                         DWORD *win32Error)
{
    HANDLE disk;
    DWORD readBytes = 0;
    BYTE raw[DPUSB_UNLOCK_METADATA_BYTES];
    DWORD storedCrc;
    DWORD actualCrc;
    LARGE_INTEGER offset;

    if (physicalPath == NULL || physicalPath[0] == L'\0' || manifest == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    disk = CreateFileW(physicalPath,
                       GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
    if (disk == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    ZeroMemory(manifest, sizeof(*manifest));
    ZeroMemory(raw, sizeof(raw));
    offset.QuadPart = (LONGLONG)DPUSB_UNLOCK_METADATA_OFFSET_BYTES;
    if (SetFilePointerEx(disk, offset, NULL, FILE_BEGIN) == 0) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseHandle(disk);
        return FALSE;
    }

    if (!ReadFile(disk, raw, sizeof(raw), &readBytes, NULL) || readBytes != sizeof(raw)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError() == ERROR_SUCCESS ? ERROR_INVALID_DATA : GetLastError();
        }
        CloseHandle(disk);
        return FALSE;
    }

    CloseHandle(disk);
    CopyMemory(manifest, raw, sizeof(*manifest));
    CopyMemory(&storedCrc, raw + DPUSB_UNLOCK_METADATA_BYTES - sizeof(DWORD), sizeof(storedCrc));
    actualCrc = Crc32Bytes(raw, DPUSB_UNLOCK_METADATA_BYTES - sizeof(DWORD));

    if (manifest->Magic != DPUSB_UNLOCK_METADATA_MAGIC ||
        manifest->Version != DPUSB_UNLOCK_METADATA_VERSION ||
        manifest->MetadataBytes != DPUSB_UNLOCK_METADATA_BYTES ||
        manifest->Algorithm != DPUSB_ALGORITHM_RC4 ||
        manifest->KeyLength == 0 ||
        manifest->KeyLength > DPUSB_MAX_KEY_BYTES ||
        manifest->KdfIterations != 200000 ||
        storedCrc != actualCrc ||
        manifest->DeviceId[0] == '\0') {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_DATA;
        }
        SecureZeroMemory(manifest, sizeof(*manifest));
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL ValidateUsbSourceRoot(const wchar_t *root, DWORD *win32Error)
{
    wchar_t physicalPath[MAX_PATH];
    DPUSB_UNLOCK_MANIFEST manifest;
    DWORD error = ERROR_SUCCESS;

    if (root == NULL || root[0] == L'\0') {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (!RootContainsUsbRuntime(root)) {
        if (win32Error != NULL) {
            *win32Error = ERROR_FILE_NOT_FOUND;
        }
        return FALSE;
    }

    if (!PhysicalPathForRoot(root, physicalPath, sizeof(physicalPath) / sizeof(physicalPath[0]), &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (GetDriveTypeW(root) != DRIVE_REMOVABLE && !IsUsbBackedPhysicalDisk(physicalPath)) {
        if (win32Error != NULL) {
            *win32Error = ERROR_NOT_SUPPORTED;
        }
        return FALSE;
    }

    ZeroMemory(&manifest, sizeof(manifest));
    if (!ReadManifestFromPhysicalPath(physicalPath, &manifest, &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    SecureZeroMemory(&manifest, sizeof(manifest));
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL LocateUsbSourceRootByApi(wchar_t *root, DWORD rootChars, DWORD *win32Error)
{
    DWORD drives;
    DWORD index;
    DWORD lastError = ERROR_NOT_FOUND;

    if (root == NULL || rootChars < 4) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    drives = GetLogicalDrives();
    if (drives == 0) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    for (index = 0; index < 26; index++) {
        wchar_t candidateRoot[4];
        DWORD error = ERROR_SUCCESS;
        UINT driveType;

        if ((drives & (1u << index)) == 0) {
            continue;
        }

        candidateRoot[0] = (wchar_t)(L'A' + index);
        candidateRoot[1] = L':';
        candidateRoot[2] = L'\\';
        candidateRoot[3] = L'\0';

        driveType = GetDriveTypeW(candidateRoot);
        if (driveType != DRIVE_REMOVABLE && driveType != DRIVE_FIXED) {
            continue;
        }

        if (!ValidateUsbSourceRoot(candidateRoot, &error)) {
            lastError = error;
            continue;
        }

        wcsncpy_s(root, rootChars, candidateRoot, _TRUNCATE);
        if (win32Error != NULL) {
            *win32Error = ERROR_SUCCESS;
        }
        return TRUE;
    }

    if (win32Error != NULL) {
        *win32Error = lastError;
    }
    return FALSE;
}

static BOOL GetUsbSourceRoot(wchar_t *root, DWORD rootChars)
{
    DWORD error = ERROR_SUCCESS;

    if (root == NULL || rootChars == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (g_UsbSourceRootSet && g_UsbSourceRoot[0] != L'\0') {
        if (ValidateUsbSourceRoot(g_UsbSourceRoot, &error)) {
            wcsncpy_s(root, rootChars, g_UsbSourceRoot, _TRUNCATE);
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }

        g_UsbSourceRootSet = FALSE;
        g_UsbSourceRoot[0] = L'\0';
    }

    if (LocateUsbSourceRootByApi(root, rootChars, &error)) {
        wcsncpy_s(g_UsbSourceRoot, sizeof(g_UsbSourceRoot) / sizeof(g_UsbSourceRoot[0]), root, _TRUNCATE);
        g_UsbSourceRootSet = TRUE;
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    SetLastError(error != ERROR_SUCCESS ? error : ERROR_NOT_FOUND);
    return FALSE;
}

static BOOL GetPhysicalDriveForVolume(wchar_t *physicalPath, DWORD physicalPathChars, DWORD *win32Error)
{
    wchar_t root[MAX_PATH];

    if (physicalPath == NULL || physicalPathChars == 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (!GetUsbSourceRoot(root, sizeof(root) / sizeof(root[0]))) {
        if (win32Error != NULL) {
            *win32Error = GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_PATH_NOT_FOUND;
        }
        return FALSE;
    }

    return PhysicalPathForRoot(root, physicalPath, physicalPathChars, win32Error);
}

static BOOL FindPackagedDriver(wchar_t *path, DWORD pathChars)
{
    wchar_t usbRoot[MAX_PATH];
    wchar_t candidate[MAX_PATH];

    if (path == NULL || pathChars == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!GetUsbSourceRoot(usbRoot, sizeof(usbRoot) / sizeof(usbRoot[0]))) {
        return FALSE;
    }

    if (swprintf_s(candidate,
                  sizeof(candidate) / sizeof(candidate[0]),
                  L"%sDataProtectorUsbRuntime\\driver\\%s",
                  usbRoot,
                  DPUSB_DRIVER_FILE_NAME) > 0 &&
        GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
        wcsncpy_s(path, pathChars, candidate, _TRUNCATE);
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

static BOOL BuildKernelDriverServicePath(const wchar_t *driverPath,
                                         DPUSB_SERVICE_PATH_MODE mode,
                                         wchar_t *servicePath,
                                         DWORD servicePathChars)
{
    wchar_t normalized[MAX_PATH];
    const wchar_t *path;

    if (driverPath == NULL || driverPath[0] == L'\0' || servicePath == NULL || servicePathChars == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (GetFullPathNameW(driverPath, sizeof(normalized) / sizeof(normalized[0]), normalized, NULL) == 0) {
        return FALSE;
    }

    path = normalized;
    if (wcsncmp(path, L"\\\\?\\", 4) == 0) {
        path += 4;
    } else if (wcsncmp(path, L"\\\\.\\", 4) == 0) {
        path += 4;
    }

    if (wcsncmp(path, L"\\??\\", 4) == 0 ||
        _wcsnicmp(path, L"\\SystemRoot\\", 12) == 0) {

        wcsncpy_s(servicePath, servicePathChars, path, _TRUNCATE);
        return servicePath[0] != L'\0';
    }

    if (wcsncmp(path, L"\\Device\\", 8) == 0) {
        wcsncpy_s(servicePath, servicePathChars, path, _TRUNCATE);
        return servicePath[0] != L'\0';
    }

    if (path[0] != L'\0' && path[1] == L':' && path[2] == L'\\') {
        if (mode == DpUsbServicePathWin32) {
            wcsncpy_s(servicePath, servicePathChars, path, _TRUNCATE);
            return TRUE;
        }

        if (StringCchPrintfW(servicePath, servicePathChars, L"\\??\\%s", path) == S_OK) {
            return TRUE;
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    SetLastError(ERROR_PATH_NOT_FOUND);
    return FALSE;
}

static BOOL InstallDriverServicePath(const wchar_t *path,
                                     DPUSB_SERVICE_PATH_MODE mode,
                                     wchar_t *installedServicePath,
                                     DWORD installedServicePathChars,
                                     DWORD *win32Error)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    BOOL ok = TRUE;
    wchar_t servicePath[MAX_PATH + 8];

    if (path == NULL || path[0] == L'\0') {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    if (!BuildKernelDriverServicePath(path, mode, servicePath, sizeof(servicePath) / sizeof(servicePath[0]))) {
        if (win32Error != NULL) {
            *win32Error = GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_PATH_NOT_FOUND;
        }
        return FALSE;
    }

    if (installedServicePath != NULL && installedServicePathChars > 0) {
        wcsncpy_s(installedServicePath, installedServicePathChars, servicePath, _TRUNCATE);
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (scm == NULL) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    service = CreateServiceW(scm,
                             DPUSB_SERVICE_NAME,
                             DPUSB_SERVICE_NAME,
                             SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS,
                             SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START,
                             SERVICE_ERROR_NORMAL,
                             servicePath,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
    if (service == NULL && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(scm,
                               DPUSB_SERVICE_NAME,
                               SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
        if (service != NULL &&
            !ChangeServiceConfigW(service,
                                  SERVICE_KERNEL_DRIVER,
                                  SERVICE_DEMAND_START,
                                  SERVICE_ERROR_NORMAL,
                                  servicePath,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL)) {
            ok = FALSE;
            if (win32Error != NULL) {
                *win32Error = GetLastError();
            }
        }
    }

    if (service == NULL) {
        ok = FALSE;
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
    }

    if (service != NULL) {
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);

    if (ok && win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return ok;
}

static BOOL StopAndDeleteDriverService(DWORD *win32Error)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS status;
    DWORD lastError = ERROR_SUCCESS;
    BOOL ok = TRUE;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    service = OpenServiceW(scm, DPUSB_SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (service != NULL) {
        if (QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED) {
            if (!ControlService(service, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
                lastError = GetLastError();
                ok = FALSE;
            }
        }

        if (!DeleteService(service) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
            lastError = GetLastError();
            ok = FALSE;
        }
        CloseServiceHandle(service);
    } else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        lastError = GetLastError();
        ok = FALSE;
    }

    CloseServiceHandle(scm);
    if (win32Error != NULL) {
        *win32Error = ok ? ERROR_SUCCESS : lastError;
    }
    return ok;
}

static BOOL StartDriverService(DWORD *win32Error)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    BOOL ok;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    service = OpenServiceW(scm, DPUSB_SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (service == NULL) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseServiceHandle(scm);
        return FALSE;
    }

    ok = StartServiceW(service, 0, NULL);
    if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
        ok = TRUE;
    }

    if (!ok && win32Error != NULL) {
        *win32Error = GetLastError();
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (ok && win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return ok;
}

static BOOL AutoPrepareDriver(wchar_t *deployedPath,
                              DWORD deployedPathChars,
                              wchar_t *servicePath,
                              DWORD servicePathChars,
                              DWORD *win32Error)
{
    DWORD error = ERROR_SUCCESS;
    wchar_t attemptedServicePath[MAX_PATH + 8];

    if (deployedPath == NULL || deployedPathChars == 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (!FindPackagedDriver(deployedPath, deployedPathChars)) {
        if (win32Error != NULL) {
            *win32Error = ERROR_FILE_NOT_FOUND;
        }
        return FALSE;
    }

    UnmountAllPrivateWorkspaces();
    (VOID)CloseSessionData(NULL);
    (VOID)StopAndDeleteDriverService(NULL);

    ZeroMemory(attemptedServicePath, sizeof(attemptedServicePath));
    if (!InstallDriverServicePath(deployedPath,
                                  DpUsbServicePathNativeDos,
                                  attemptedServicePath,
                                  sizeof(attemptedServicePath) / sizeof(attemptedServicePath[0]),
                                  &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (servicePath != NULL && servicePathChars > 0) {
        wcsncpy_s(servicePath, servicePathChars, attemptedServicePath, _TRUNCATE);
    }

    if (!StartDriverService(&error)) {
        if (IsExpectedDriverNotLoadedError(error)) {
            (VOID)StopAndDeleteDriverService(NULL);
            if (!InstallDriverServicePath(deployedPath,
                                          DpUsbServicePathWin32,
                                          attemptedServicePath,
                                          sizeof(attemptedServicePath) / sizeof(attemptedServicePath[0]),
                                          &error) ||
                !StartDriverService(&error)) {

                if (servicePath != NULL && servicePathChars > 0 && attemptedServicePath[0] != L'\0') {
                    wcsncpy_s(servicePath, servicePathChars, attemptedServicePath, _TRUNCATE);
                }
                if (win32Error != NULL) {
                    *win32Error = error;
                }
                return FALSE;
            }

            if (servicePath != NULL && servicePathChars > 0) {
                wcsncpy_s(servicePath, servicePathChars, attemptedServicePath, _TRUNCATE);
            }
            if (win32Error != NULL) {
                *win32Error = ERROR_SUCCESS;
            }
            return TRUE;
        }

        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL DriveLetterIsAvailable(WCHAR letter)
{
    WCHAR root[4];

    swprintf_s(root, sizeof(root) / sizeof(root[0]), L"%c:\\", letter);
    return GetDriveTypeW(root) == DRIVE_NO_ROOT_DIR;
}

static BOOL BuildGlobalDosName(WCHAR letter, wchar_t *dosName, DWORD dosNameChars)
{
    if (dosName == NULL || dosNameChars < 12) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    return swprintf_s(dosName, dosNameChars, L"Global\\%c:", letter) > 0;
}

static BOOL BuildLocalDosName(WCHAR letter, wchar_t *dosName, DWORD dosNameChars)
{
    if (dosName == NULL || dosNameChars < 3) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    return swprintf_s(dosName, dosNameChars, L"%c:", letter) > 0;
}

static BOOL RemoveDosDeviceDefinition(const wchar_t *dosName, const wchar_t *target)
{
    BOOL removed = TRUE;
    DWORD error = ERROR_SUCCESS;
    const wchar_t *exactTarget = target != NULL ? target : DPUSB_NT_DEVICE_NAME;

    if (dosName == NULL || dosName[0] == L'\0') {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    while (DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE | DDD_NO_BROADCAST_SYSTEM,
                            dosName,
                            exactTarget)) {
        removed = TRUE;
    }

    error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_SUCCESS) {
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    SetLastError(error);
    return removed && error == ERROR_SUCCESS;
}

static BOOL TryCreatePrivateWorkspaceLink(WCHAR letter, BOOL globalLink, DPUSB_PRIVATE_MOUNT *mount, DWORD *win32Error)
{
    WCHAR dosName[16];
    WCHAR path[8];
    DWORD error;

    if (mount == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (globalLink) {
        if (!BuildGlobalDosName(letter, dosName, sizeof(dosName) / sizeof(dosName[0]))) {
            if (win32Error != NULL) {
                *win32Error = GetLastError();
            }
            return FALSE;
        }
    } else if (!BuildLocalDosName(letter, dosName, sizeof(dosName) / sizeof(dosName[0]))) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    swprintf_s(path, sizeof(path) / sizeof(path[0]), L"%c:\\", letter);
    (VOID)RemoveDosDeviceDefinition(dosName, DPUSB_NT_DEVICE_NAME);
    if (DefineDosDeviceW(DDD_RAW_TARGET_PATH, dosName, DPUSB_NT_DEVICE_NAME)) {
        mount->Letter = letter;
        wcsncpy_s(mount->DosName, sizeof(mount->DosName) / sizeof(mount->DosName[0]), dosName, _TRUNCATE);
        wcsncpy_s(mount->Path, sizeof(mount->Path) / sizeof(mount->Path[0]), path, _TRUNCATE);
        if (globalLink) {
            AppendLog(L"Private workspace drive letter created globally: %s", path);
        } else {
            AppendLog(L"Private workspace drive letter created for the current logon session only: %s", path);
        }
        if (win32Error != NULL) {
            *win32Error = ERROR_SUCCESS;
        }
        return TRUE;
    }

    error = GetLastError();
    if (win32Error != NULL) {
        *win32Error = error;
    }
    return FALSE;
}

static BOOL RequestKernelDriveMount(WCHAR letter, DWORD *win32Error)
{
    HANDLE device;
    DPUSB_DRIVE_MOUNT request;
    DWORD returned = 0;

    device = OpenControlDevice(GENERIC_READ | GENERIC_WRITE);
    if (device == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    ZeroMemory(&request, sizeof(request));
    request.Version = 1;
    request.DriveLetter = letter;
    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_MOUNT_DRIVE,
                         &request,
                         sizeof(request),
                         NULL,
                         0,
                         &returned,
                         NULL)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseHandle(device);
        return FALSE;
    }

    CloseHandle(device);
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static void RequestKernelDriveUnmount(WCHAR letter)
{
    HANDLE device;
    DPUSB_DRIVE_MOUNT request;
    DWORD returned = 0;

    if (letter == L'\0') {
        return;
    }

    device = OpenControlDevice(GENERIC_READ | GENERIC_WRITE);
    if (device == INVALID_HANDLE_VALUE) {
        return;
    }

    ZeroMemory(&request, sizeof(request));
    request.Version = 1;
    request.DriveLetter = letter;
    (VOID)DeviceIoControl(device,
                          IOCTL_DPUSB_UNMOUNT_DRIVE,
                          &request,
                          sizeof(request),
                          NULL,
                          0,
                          &returned,
                          NULL);
    CloseHandle(device);
}

static BOOL MountPrivateWorkspace(DPUSB_PRIVATE_MOUNT *mount, DWORD *win32Error)
{
    WCHAR letter;
    DWORD error = ERROR_SUCCESS;
    DWORD privilegeError = ERROR_SUCCESS;
    DWORD globalError = ERROR_SUCCESS;
    BOOL globalPrivilegeEnabled;

    if (mount == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    ZeroMemory(mount, sizeof(*mount));
    UnmountAllPrivateWorkspaces();
    globalPrivilegeEnabled = EnableProcessPrivilege(SE_CREATE_GLOBAL_NAME, &privilegeError);
    if (!globalPrivilegeEnabled) {
        AppendLog(L"Global drive-letter privilege is unavailable; falling back if needed. Win32=%lu", privilegeError);
    }

    for (letter = L'Z'; letter >= L'M'; letter--) {
        if (!DriveLetterIsAvailable(letter)) {
            continue;
        }

        if (RequestKernelDriveMount(letter, &error)) {
            WCHAR globalName[16];
            WCHAR path[8];

            swprintf_s(path, sizeof(path) / sizeof(path[0]), L"%c:\\", letter);
            if (!BuildGlobalDosName(letter, globalName, sizeof(globalName) / sizeof(globalName[0]))) {
                RequestKernelDriveUnmount(letter);
                error = GetLastError();
                continue;
            }

            mount->Letter = letter;
            wcsncpy_s(mount->DosName, sizeof(mount->DosName) / sizeof(mount->DosName[0]), globalName, _TRUNCATE);
            wcsncpy_s(mount->Path, sizeof(mount->Path) / sizeof(mount->Path[0]), path, _TRUNCATE);
            AppendLog(L"Private workspace drive letter created by kernel: %s", path);
            if (win32Error != NULL) {
                *win32Error = ERROR_SUCCESS;
            }
            return TRUE;
        }

        if (error == ERROR_ACCESS_DENIED) {
            AppendLog(L"Kernel drive-letter creation was denied; trying user-mode fallback.");
        }

        if (globalPrivilegeEnabled && TryCreatePrivateWorkspaceLink(letter, TRUE, mount, &globalError)) {
            if (win32Error != NULL) {
                *win32Error = ERROR_SUCCESS;
            }
            return TRUE;
        }

        error = globalError != ERROR_SUCCESS ? globalError : error;
        if (globalPrivilegeEnabled && globalError == ERROR_ACCESS_DENIED) {
            AppendLog(L"Global drive-letter creation was denied; using current-session mapping fallback.");
        }

        if (TryCreatePrivateWorkspaceLink(letter, FALSE, mount, &error)) {
            if (win32Error != NULL) {
                *win32Error = ERROR_SUCCESS;
            }
            return TRUE;
        }
    }

    if (win32Error != NULL) {
        *win32Error = error != ERROR_SUCCESS ? error : ERROR_NO_MORE_ITEMS;
    }
    return FALSE;
}

static void UnmountPrivateWorkspace(const DPUSB_PRIVATE_MOUNT *mount)
{
    if (mount == NULL || mount->DosName[0] == L'\0') {
        return;
    }

    RequestKernelDriveUnmount(mount->Letter);
    (VOID)RemoveDosDeviceDefinition(mount->DosName, DPUSB_NT_DEVICE_NAME);
}

static void UnmountAllPrivateWorkspaces(void)
{
    WCHAR letter;
    WCHAR dosName[16];
    WCHAR localDosName[8];
    WCHAR target[512];

    for (letter = L'A'; letter <= L'Z'; letter++) {
        if (!BuildGlobalDosName(letter, dosName, sizeof(dosName) / sizeof(dosName[0]))) {
            continue;
        }

        ZeroMemory(target, sizeof(target));
        if (QueryDosDeviceW(dosName, target, sizeof(target) / sizeof(target[0])) == 0) {
            swprintf_s(localDosName, sizeof(localDosName) / sizeof(localDosName[0]), L"%c:", letter);
            ZeroMemory(target, sizeof(target));
            if (QueryDosDeviceW(localDosName, target, sizeof(target) / sizeof(target[0])) == 0) {
                continue;
            }
        }

        if (_wcsicmp(target, DPUSB_NT_DEVICE_NAME) == 0) {
            (VOID)RemoveDosDeviceDefinition(dosName, DPUSB_NT_DEVICE_NAME);
            swprintf_s(localDosName, sizeof(localDosName) / sizeof(localDosName[0]), L"%c:", letter);
            (VOID)RemoveDosDeviceDefinition(localDosName, DPUSB_NT_DEVICE_NAME);
        }
    }
}

static BOOL FlushDismountVolumeByRoot(const wchar_t *root, BOOL preventRemoval, DWORD *win32Error)
{
    WCHAR volumePath[16];
    HANDLE volume;
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;
    BOOL ok = TRUE;
    BOOL locked = FALSE;

    if (root == NULL || root[0] == L'\0' || root[1] != L':') {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (swprintf_s(volumePath,
                   sizeof(volumePath) / sizeof(volumePath[0]),
                   L"\\\\.\\%c:",
                   root[0]) <= 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INSUFFICIENT_BUFFER;
        }
        return FALSE;
    }

    volume = CreateFileW(volumePath,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (volume == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    if (!FlushFileBuffers(volume)) {
        error = GetLastError();
        ok = FALSE;
    }

    if (DeviceIoControl(volume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &returned, NULL)) {
        locked = TRUE;
    } else if (ok) {
        error = GetLastError();
        ok = FALSE;
    }

    if (!DeviceIoControl(volume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &returned, NULL) && ok) {
        error = GetLastError();
        ok = FALSE;
    }

    if (preventRemoval) {
        PREVENT_MEDIA_REMOVAL removal;

        ZeroMemory(&removal, sizeof(removal));
        removal.PreventMediaRemoval = FALSE;
        if (!DeviceIoControl(volume,
                             IOCTL_STORAGE_MEDIA_REMOVAL,
                             &removal,
                             sizeof(removal),
                             NULL,
                             0,
                             &returned,
                             NULL) && ok) {
            error = GetLastError();
            ok = FALSE;
        }

        if (!DeviceIoControl(volume, IOCTL_STORAGE_EJECT_MEDIA, NULL, 0, NULL, 0, &returned, NULL) && ok) {
            error = GetLastError();
            ok = FALSE;
        }
    }

    if (locked) {
        (VOID)DeviceIoControl(volume, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &returned, NULL);
    }
    CloseHandle(volume);

    if (win32Error != NULL) {
        *win32Error = ok ? ERROR_SUCCESS : error;
    }
    return ok;
}

static BOOL FlushDismountPrivateWorkspace(DWORD *win32Error)
{
    WCHAR letter;
    WCHAR root[4];
    WCHAR dosName[16];
    WCHAR localDosName[8];
    WCHAR target[512];
    DWORD firstError = ERROR_SUCCESS;

    for (letter = L'A'; letter <= L'Z'; letter++) {
        if (!BuildGlobalDosName(letter, dosName, sizeof(dosName) / sizeof(dosName[0]))) {
            continue;
        }

        ZeroMemory(target, sizeof(target));
        if (QueryDosDeviceW(dosName, target, sizeof(target) / sizeof(target[0])) == 0) {
            swprintf_s(localDosName, sizeof(localDosName) / sizeof(localDosName[0]), L"%c:", letter);
            ZeroMemory(target, sizeof(target));
            if (QueryDosDeviceW(localDosName, target, sizeof(target) / sizeof(target[0])) == 0) {
                continue;
            }
        }

        if (_wcsicmp(target, DPUSB_NT_DEVICE_NAME) == 0) {
            DWORD error = ERROR_SUCCESS;
            BOOL unmounted;

            swprintf_s(root, sizeof(root) / sizeof(root[0]), L"%c:\\", letter);
            unmounted = FlushDismountVolumeByRoot(root, FALSE, &error);
            if (!unmounted && firstError == ERROR_SUCCESS) {
                firstError = error;
            }

            if (unmounted) {
                RequestKernelDriveUnmount(letter);
                (VOID)RemoveDosDeviceDefinition(dosName, DPUSB_NT_DEVICE_NAME);
                swprintf_s(localDosName, sizeof(localDosName) / sizeof(localDosName[0]), L"%c:", letter);
                (VOID)RemoveDosDeviceDefinition(localDosName, DPUSB_NT_DEVICE_NAME);
            }
        }
    }

    if (win32Error != NULL) {
        *win32Error = firstError;
    }
    return firstError == ERROR_SUCCESS;
}

static BOOL OpenMountedWorkspaceHandle(const DPUSB_PRIVATE_MOUNT *mount, DWORD access, HANDLE *handle, DWORD *win32Error)
{
    WCHAR volumePath[8];
    HANDLE volume;

    if (mount == NULL || mount->Letter == L'\0' || handle == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    swprintf_s(volumePath, sizeof(volumePath) / sizeof(volumePath[0]), L"\\\\.\\%c:", mount->Letter);
    volume = CreateFileW(volumePath,
                         access,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (volume == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    *handle = volume;
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL ValidateMountedWorkspaceDevice(const DPUSB_PRIVATE_MOUNT *mount, DWORD *win32Error)
{
    HANDLE volume = INVALID_HANDLE_VALUE;
    STORAGE_DEVICE_NUMBER deviceNumber;
    DWORD returned = 0;

    if (!OpenMountedWorkspaceHandle(mount, 0, &volume, win32Error)) {
        return FALSE;
    }

    ZeroMemory(&deviceNumber, sizeof(deviceNumber));
    if (!DeviceIoControl(volume,
                         IOCTL_STORAGE_GET_DEVICE_NUMBER,
                         NULL,
                         0,
                         &deviceNumber,
                         sizeof(deviceNumber),
                         &returned,
                         NULL)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseHandle(volume);
        return FALSE;
    }

    CloseHandle(volume);
    if (deviceNumber.DeviceNumber != DPUSB_VIRTUAL_DEVICE_NUMBER) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_DATA;
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL QueryWorkspaceFileSystem(const DPUSB_PRIVATE_MOUNT *mount,
                                     wchar_t *fileSystem,
                                     DWORD fileSystemChars,
                                     DWORD *win32Error)
{
    WCHAR label[MAX_PATH + 1];
    DWORD serialNumber = 0;
    DWORD maximumComponentLength = 0;
    DWORD fileSystemFlags = 0;

    if (mount == NULL || fileSystem == NULL || fileSystemChars == 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    fileSystem[0] = L'\0';
    ZeroMemory(label, sizeof(label));
    if (!GetVolumeInformationW(mount->Path,
                               label,
                               sizeof(label) / sizeof(label[0]),
                               &serialNumber,
                               &maximumComponentLength,
                               &fileSystemFlags,
                               fileSystem,
                               fileSystemChars)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

typedef struct _DPUSB_FAT32_LAYOUT {
    DWORD TotalSectors;
    DWORD SectorsPerFat;
    DWORD ReservedSectors;
    DWORD SectorsPerCluster;
    DWORD RootCluster;
    DWORD Fat1Sector;
    DWORD Fat2Sector;
    DWORD DataStartSector;
    DWORD ClusterCount;
    DWORD VolumeSerial;
} DPUSB_FAT32_LAYOUT;

static void WriteLe16(BYTE *target, WORD value)
{
    target[0] = (BYTE)(value & 0xFF);
    target[1] = (BYTE)((value >> 8) & 0xFF);
}

static void WriteLe32(BYTE *target, DWORD value)
{
    target[0] = (BYTE)(value & 0xFF);
    target[1] = (BYTE)((value >> 8) & 0xFF);
    target[2] = (BYTE)((value >> 16) & 0xFF);
    target[3] = (BYTE)((value >> 24) & 0xFF);
}

static BOOL WriteWorkspaceBytes(HANDLE volume,
                                ULONGLONG offset,
                                const void *buffer,
                                DWORD bytes,
                                DWORD *win32Error)
{
    LARGE_INTEGER position;
    DWORD written = 0;

    if (volume == INVALID_HANDLE_VALUE || buffer == NULL || bytes == 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    position.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(volume, position, NULL, FILE_BEGIN) ||
        !WriteFile(volume, buffer, bytes, &written, NULL) ||
        written != bytes) {

        if (win32Error != NULL) {
            *win32Error = GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_WRITE_FAULT;
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL ZeroWorkspaceRange(HANDLE volume,
                               ULONGLONG offset,
                               ULONGLONG bytes,
                               DWORD *win32Error)
{
    BYTE zero[64 * 1024];
    ULONGLONG remaining = bytes;

    ZeroMemory(zero, sizeof(zero));
    while (remaining != 0) {
        DWORD chunk = remaining > sizeof(zero) ? (DWORD)sizeof(zero) : (DWORD)remaining;
        if (!WriteWorkspaceBytes(volume, offset, zero, chunk, win32Error)) {
            return FALSE;
        }

        offset += chunk;
        remaining -= chunk;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static DWORD CalculateFat32SectorsPerCluster(ULONGLONG totalBytes)
{
    ULONGLONG totalMb = totalBytes / (1024ull * 1024ull);

    if (totalMb < 260) {
        return 1;
    }
    if (totalMb < 8192) {
        return 8;
    }
    if (totalMb < 16384) {
        return 16;
    }
    if (totalMb < 32768) {
        return 32;
    }
    return 64;
}

static BOOL CalculateFat32Layout(ULONGLONG totalBytes, DPUSB_FAT32_LAYOUT *layout)
{
    DWORD totalSectors;
    DWORD sectorsPerCluster;
    DWORD sectorsPerFat = 0;
    DWORD reservedSectors = 32;
    DWORD fatCount = 2;
    DWORD previous;
    DWORD clusterCount;
    DWORD dataSectors;
    DWORD rootDirectorySectors = 0;
    DWORD iterations;

    if (layout == NULL || totalBytes < (64ull * 1024ull * 1024ull)) {
        return FALSE;
    }

    totalSectors = (DWORD)(totalBytes / 512ull);
    sectorsPerCluster = CalculateFat32SectorsPerCluster(totalBytes);
    if (sectorsPerCluster == 0) {
        return FALSE;
    }

    for (iterations = 0; iterations < 32; iterations++) {
        ULONGLONG fatBytes;

        if (totalSectors <= reservedSectors + (fatCount * sectorsPerFat)) {
            return FALSE;
        }

        dataSectors = totalSectors - reservedSectors - (fatCount * sectorsPerFat) - rootDirectorySectors;
        clusterCount = dataSectors / sectorsPerCluster;
        fatBytes = ((ULONGLONG)clusterCount + 2ull) * sizeof(DWORD);
        previous = sectorsPerFat;
        sectorsPerFat = (DWORD)((fatBytes + 511ull) / 512ull);
        if (sectorsPerFat == previous) {
            break;
        }
    }

    dataSectors = totalSectors - reservedSectors - (fatCount * sectorsPerFat);
    clusterCount = dataSectors / sectorsPerCluster;
    if (clusterCount < 65525) {
        return FALSE;
    }

    ZeroMemory(layout, sizeof(*layout));
    layout->TotalSectors = totalSectors;
    layout->SectorsPerFat = sectorsPerFat;
    layout->ReservedSectors = reservedSectors;
    layout->SectorsPerCluster = sectorsPerCluster;
    layout->RootCluster = 2;
    layout->Fat1Sector = reservedSectors;
    layout->Fat2Sector = reservedSectors + sectorsPerFat;
    layout->DataStartSector = reservedSectors + (fatCount * sectorsPerFat);
    layout->ClusterCount = clusterCount;
    layout->VolumeSerial = ((DWORD)GetTickCount() << 16) ^ GetCurrentProcessId();
    return TRUE;
}

static void BuildFat32BootSector(const DPUSB_FAT32_LAYOUT *layout, BOOL backupBoot, BYTE sector[512])
{
    static const BYTE bootstrap[] = {
        0xFA, 0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C,
        0xFB, 0x8E, 0xD8, 0x8E, 0xC0, 0xBE, 0x74, 0x7C,
        0xAC, 0x22, 0xC0, 0x74, 0x06, 0xB4, 0x0E, 0xCD,
        0x10, 0xEB, 0xF5, 0xF4, 0xEB, 0xFD
    };

    ZeroMemory(sector, 512);
    sector[0] = 0xEB;
    sector[1] = 0x58;
    sector[2] = 0x90;
    CopyMemory(&sector[3], "MSWIN4.1", 8);
    WriteLe16(&sector[11], 512);
    sector[13] = (BYTE)layout->SectorsPerCluster;
    WriteLe16(&sector[14], (WORD)layout->ReservedSectors);
    sector[16] = 2;
    WriteLe16(&sector[17], 0);
    WriteLe16(&sector[19], 0);
    sector[21] = 0xF8;
    WriteLe16(&sector[22], 0);
    WriteLe16(&sector[24], 63);
    WriteLe16(&sector[26], 255);
    WriteLe32(&sector[28], 0);
    WriteLe32(&sector[32], layout->TotalSectors);
    WriteLe32(&sector[36], layout->SectorsPerFat);
    WriteLe16(&sector[40], 0);
    WriteLe16(&sector[42], 0);
    WriteLe32(&sector[44], layout->RootCluster);
    WriteLe16(&sector[48], 1);
    WriteLe16(&sector[50], 6);
    sector[64] = 0x80;
    sector[66] = 0x29;
    WriteLe32(&sector[67], layout->VolumeSerial);
    CopyMemory(&sector[71], "DPUSBPRIVATE", 11);
    CopyMemory(&sector[82], "FAT32   ", 8);
    if (!backupBoot) {
        CopyMemory(&sector[90], bootstrap, sizeof(bootstrap));
        CopyMemory(&sector[122], "DataProtector Secure USB\r\n", 26);
    }
    sector[510] = 0x55;
    sector[511] = 0xAA;
}

static void BuildFat32FsInfo(const DPUSB_FAT32_LAYOUT *layout, BYTE sector[512])
{
    ZeroMemory(sector, 512);
    WriteLe32(&sector[0], 0x41615252);
    WriteLe32(&sector[484], 0x61417272);
    WriteLe32(&sector[488], layout->ClusterCount > 1 ? layout->ClusterCount - 1 : 0xFFFFFFFF);
    WriteLe32(&sector[492], 3);
    WriteLe32(&sector[508], 0xAA550000);
}

static void BuildFat32FatStart(BYTE sector[512])
{
    ZeroMemory(sector, 512);
    WriteLe32(&sector[0], 0x0FFFFFF8);
    WriteLe32(&sector[4], 0x0FFFFFFF);
    WriteLe32(&sector[8], 0x0FFFFFFF);
}

static BOOL InitializeWorkspaceFat32Container(HANDLE volume,
                                              ULONGLONG totalBytes,
                                              DWORD *win32Error)
{
    DPUSB_FAT32_LAYOUT layout;
    BYTE sector[512];
    ULONGLONG fatBytes;
    ULONGLONG rootOffset;

    if (!CalculateFat32Layout(totalBytes, &layout)) {
        if (win32Error != NULL) {
            *win32Error = ERROR_DISK_FULL;
        }
        return FALSE;
    }

    AppendLog(L"Writing FAT32 container metadata directly to the encrypted data region. Size=%I64u MB, cluster=%lu sectors, FAT=%lu sectors.",
              totalBytes / (1024ull * 1024ull),
              layout.SectorsPerCluster,
              layout.SectorsPerFat);

    if (!ZeroWorkspaceRange(volume,
                            0,
                            ((ULONGLONG)layout.DataStartSector + layout.SectorsPerCluster) * 512ull,
                            win32Error)) {
        return FALSE;
    }

    BuildFat32BootSector(&layout, FALSE, sector);
    if (!WriteWorkspaceBytes(volume, 0, sector, sizeof(sector), win32Error)) {
        return FALSE;
    }

    BuildFat32FsInfo(&layout, sector);
    if (!WriteWorkspaceBytes(volume, 512ull, sector, sizeof(sector), win32Error)) {
        return FALSE;
    }

    BuildFat32BootSector(&layout, TRUE, sector);
    if (!WriteWorkspaceBytes(volume, 6ull * 512ull, sector, sizeof(sector), win32Error)) {
        return FALSE;
    }

    BuildFat32FsInfo(&layout, sector);
    if (!WriteWorkspaceBytes(volume, 7ull * 512ull, sector, sizeof(sector), win32Error)) {
        return FALSE;
    }

    BuildFat32FatStart(sector);
    fatBytes = (ULONGLONG)layout.SectorsPerFat * 512ull;
    if (!WriteWorkspaceBytes(volume, (ULONGLONG)layout.Fat1Sector * 512ull, sector, sizeof(sector), win32Error) ||
        !WriteWorkspaceBytes(volume, (ULONGLONG)layout.Fat2Sector * 512ull, sector, sizeof(sector), win32Error)) {
        return FALSE;
    }

    if (fatBytes > sizeof(sector)) {
        if (!ZeroWorkspaceRange(volume,
                                ((ULONGLONG)layout.Fat1Sector * 512ull) + sizeof(sector),
                                fatBytes - sizeof(sector),
                                win32Error) ||
            !ZeroWorkspaceRange(volume,
                                ((ULONGLONG)layout.Fat2Sector * 512ull) + sizeof(sector),
                                fatBytes - sizeof(sector),
                                win32Error)) {
            return FALSE;
        }
    }

    rootOffset = ((ULONGLONG)layout.DataStartSector +
                  ((ULONGLONG)(layout.RootCluster - 2) * layout.SectorsPerCluster)) * 512ull;
    if (!ZeroWorkspaceRange(volume, rootOffset, (ULONGLONG)layout.SectorsPerCluster * 512ull, win32Error)) {
        return FALSE;
    }

    FlushFileBuffers(volume);
    (VOID)fatBytes;
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL EnsurePrivateWorkspaceFileSystem(const DPUSB_PRIVATE_MOUNT *mount, DWORD *win32Error)
{
    WCHAR fileSystem[32];
    DWORD error = ERROR_SUCCESS;
    DWORD attempt;
    HANDLE volume = INVALID_HANDLE_VALUE;
    GET_LENGTH_INFORMATION lengthInfo;
    DWORD returned = 0;

    if (!ValidateMountedWorkspaceDevice(mount, &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    for (attempt = 0; attempt < 6; attempt++) {
        if (QueryWorkspaceFileSystem(mount, fileSystem, sizeof(fileSystem) / sizeof(fileSystem[0]), &error)) {
            if (_wcsicmp(fileSystem, L"NTFS") == 0 ||
                _wcsicmp(fileSystem, L"FAT32") == 0 ||
                _wcsicmp(fileSystem, L"exFAT") == 0) {
                (VOID)SetVolumeLabelW(mount->Path, DPUSB_PRIVATE_VOLUME_LABEL);
                if (win32Error != NULL) {
                    *win32Error = ERROR_SUCCESS;
                }
                return TRUE;
            }
            break;
        }

        if (error != ERROR_UNRECOGNIZED_VOLUME &&
            error != ERROR_NOT_READY &&
            error != ERROR_INVALID_PARAMETER &&
            error != ERROR_FILE_SYSTEM_LIMITATION) {
            break;
        }

        Sleep(500);
    }

    AppendLog(L"Private workspace has no file system yet. Initializing encrypted FAT32 container in-place...");
    if (!OpenMountedWorkspaceHandle(mount, GENERIC_READ | GENERIC_WRITE, &volume, &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    ZeroMemory(&lengthInfo, sizeof(lengthInfo));
    if (!DeviceIoControl(volume,
                         IOCTL_DISK_GET_LENGTH_INFO,
                         NULL,
                         0,
                         &lengthInfo,
                         sizeof(lengthInfo),
                         &returned,
                         NULL)) {
        error = GetLastError();
        CloseHandle(volume);
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (!InitializeWorkspaceFat32Container(volume, (ULONGLONG)lengthInfo.Length.QuadPart, &error)) {
        CloseHandle(volume);
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    (VOID)DeviceIoControl(volume, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &returned, NULL);
    (VOID)DeviceIoControl(volume, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &returned, NULL);
    CloseHandle(volume);
    RequestKernelDriveUnmount(mount->Letter);
    Sleep(500);
    if (!RequestKernelDriveMount(mount->Letter, &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    for (attempt = 0; attempt < 12; attempt++) {
        if (QueryWorkspaceFileSystem(mount, fileSystem, sizeof(fileSystem) / sizeof(fileSystem[0]), &error) &&
            (_wcsicmp(fileSystem, L"FAT32") == 0 ||
             _wcsicmp(fileSystem, L"NTFS") == 0 ||
             _wcsicmp(fileSystem, L"exFAT") == 0)) {

            (VOID)SetVolumeLabelW(mount->Path, DPUSB_PRIVATE_VOLUME_LABEL);
            if (win32Error != NULL) {
                *win32Error = ERROR_SUCCESS;
            }
            return TRUE;
        }

        Sleep(500);
    }

    if (win32Error != NULL) {
        *win32Error = error != ERROR_SUCCESS ? error : ERROR_UNRECOGNIZED_VOLUME;
    }
    return FALSE;
}

static DWORD ReadFixedUtf8(const CHAR *source, DWORD sourceBytes, wchar_t *target, DWORD targetChars)
{
    DWORD length;
    int converted;

    if (source == NULL || sourceBytes == 0 || target == NULL || targetChars == 0) {
        return 0;
    }

    target[0] = L'\0';
    for (length = 0; length < sourceBytes && source[length] != '\0'; length++) {
    }

    if (length == 0) {
        return 0;
    }

    converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, (int)length, target, (int)targetChars - 1);
    if (converted <= 0) {
        return 0;
    }

    target[converted] = L'\0';
    return (DWORD)converted;
}

static DWORD Crc32Bytes(const BYTE *bytes, DWORD count)
{
    DWORD crc = 0xFFFFFFFFUL;
    DWORD index;
    int bit;

    if (bytes == NULL) {
        return 0;
    }

    for (index = 0; index < count; index++) {
        crc ^= bytes[index];
        for (bit = 0; bit < 8; bit++) {
            crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
        }
    }

    return ~crc;
}

static BOOL ReadUnlockManifest(DPUSB_UNLOCK_MANIFEST *manifest, DWORD *win32Error)
{
    wchar_t physicalPath[MAX_PATH];

    if (manifest == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    if (!GetPhysicalDriveForVolume(physicalPath, sizeof(physicalPath) / sizeof(physicalPath[0]), win32Error)) {
        return FALSE;
    }

    return ReadManifestFromPhysicalPath(physicalPath, manifest, win32Error);
}

static BOOL DeriveUnlockBytes(const wchar_t *password,
                              const BYTE *salt,
                              BYTE *output,
                              DWORD outputLength,
                              DWORD *win32Error)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS status;
    ULONG passwordBytes;

    if (password == NULL || password[0] == L'\0' || salt == NULL || output == NULL || outputLength == 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    passwordBytes = (ULONG)(wcslen(password) * sizeof(wchar_t));
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_FUNCTION;
        }
        return FALSE;
    }

    status = BCryptDeriveKeyPBKDF2(algorithm,
                                   (PUCHAR)password,
                                   passwordBytes,
                                   (PUCHAR)salt,
                                   DPUSB_PASSWORD_SALT_BYTES,
                                   200000,
                                   output,
                                   outputLength,
                                   0);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_DATA;
        }
        return FALSE;
    }

    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL ConstantTimeEquals(const BYTE *left, const BYTE *right, DWORD length)
{
    BYTE diff = 0;
    DWORD index;

    if (left == NULL || right == NULL || length == 0) {
        return FALSE;
    }

    for (index = 0; index < length; index++) {
        diff |= (BYTE)(left[index] ^ right[index]);
    }

    return diff == 0;
}

static BOOL UnlockSecretFromPassword(const wchar_t *password, DPUSB_UNLOCK_SECRET *secret, DWORD *win32Error)
{
    DPUSB_UNLOCK_MANIFEST manifest;
    BYTE derived[DPUSB_UNLOCK_KDF_BYTES];
    DWORD index;
    DWORD error = ERROR_SUCCESS;
    wchar_t deviceId[DPUSB_MAX_DEVICE_ID_CHARS];
    wchar_t physicalPath[128];

    if (secret == NULL) {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    ZeroMemory(secret, sizeof(*secret));
    ZeroMemory(&manifest, sizeof(manifest));
    ZeroMemory(derived, sizeof(derived));
    ZeroMemory(physicalPath, sizeof(physicalPath));

    if (!GetPhysicalDriveForVolume(physicalPath, sizeof(physicalPath) / sizeof(physicalPath[0]), &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (!ReadUnlockManifest(&manifest, &error)) {
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (!DeriveUnlockBytes(password, manifest.PasswordSalt, derived, sizeof(derived), &error)) {
        SecureZeroMemory(&manifest, sizeof(manifest));
        if (win32Error != NULL) {
            *win32Error = error;
        }
        return FALSE;
    }

    if (!ConstantTimeEquals(derived, manifest.PasswordVerifier, DPUSB_PASSWORD_VERIFIER_BYTES)) {
        SecureZeroMemory(&manifest, sizeof(manifest));
        SecureZeroMemory(derived, sizeof(derived));
        if (win32Error != NULL) {
            *win32Error = ERROR_ACCESS_DENIED;
        }
        return FALSE;
    }

    secret->KeyLength = manifest.KeyLength;
    secret->ToolAreaBytes = DPUSB_PUBLIC_TOOL_BYTES;
    secret->DataOffsetBytes = manifest.DataOffsetBytes < DPUSB_DATA_OFFSET_BYTES ? DPUSB_DATA_OFFSET_BYTES : manifest.DataOffsetBytes;
    secret->DataLengthBytes = manifest.DataLengthBytes;
    ZeroMemory(deviceId, sizeof(deviceId));
    if (ReadFixedUtf8(manifest.DeviceId,
                      sizeof(manifest.DeviceId),
                      deviceId,
                      sizeof(deviceId) / sizeof(deviceId[0])) == 0) {
        SecureZeroMemory(&manifest, sizeof(manifest));
        SecureZeroMemory(derived, sizeof(derived));
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_DATA;
        }
        return FALSE;
    }

    wcsncpy_s(secret->DeviceId,
              sizeof(secret->DeviceId) / sizeof(secret->DeviceId[0]),
              deviceId,
              _TRUNCATE);
    wcsncpy_s(secret->PhysicalDrivePath,
              sizeof(secret->PhysicalDrivePath) / sizeof(secret->PhysicalDrivePath[0]),
              physicalPath,
              _TRUNCATE);

    for (index = 0; index < secret->KeyLength; index++) {
        secret->Key[index] = (BYTE)(manifest.WrappedKey[index] ^ derived[DPUSB_PASSWORD_VERIFIER_BYTES + index]);
    }

    SecureZeroMemory(&manifest, sizeof(manifest));
    SecureZeroMemory(derived, sizeof(derived));
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static BOOL OpenSessionWithSecret(const DPUSB_UNLOCK_SECRET *secret, DWORD *win32Error)
{
    HANDLE device;
    DPUSB_OPEN_SESSION request;
    DWORD returned = 0;

    if (secret == NULL || secret->KeyLength == 0 || secret->KeyLength > DPUSB_MAX_KEY_BYTES || secret->DeviceId[0] == L'\0') {
        if (win32Error != NULL) {
            *win32Error = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    ZeroMemory(&request, sizeof(request));
    request.Version = 1;
    request.Algorithm = DPUSB_ALGORITHM_RC4;
    request.ToolAreaBytes = secret->ToolAreaBytes < DPUSB_MIN_TOOL_BYTES ? DPUSB_MIN_TOOL_BYTES : secret->ToolAreaBytes;
    request.DataOffsetBytes = secret->DataOffsetBytes;
    request.DataLengthBytes = secret->DataLengthBytes;
    request.KeyLength = secret->KeyLength;
    wcsncpy_s(request.PhysicalDrivePath,
              sizeof(request.PhysicalDrivePath) / sizeof(request.PhysicalDrivePath[0]),
              secret->PhysicalDrivePath,
              _TRUNCATE);
    CopyMemory(request.Key, secret->Key, secret->KeyLength);
    wcsncpy_s(request.DeviceId,
              sizeof(request.DeviceId) / sizeof(request.DeviceId[0]),
              secret->DeviceId,
              _TRUNCATE);

    device = OpenControlDevice(GENERIC_READ | GENERIC_WRITE);
    if (device == INVALID_HANDLE_VALUE) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        SecureZeroMemory(&request, sizeof(request));
        return FALSE;
    }

    if (!DeviceIoControl(device,
                         IOCTL_DPUSB_OPEN_SESSION,
                         &request,
                         sizeof(request),
                         NULL,
                         0,
                         &returned,
                         NULL)) {
        if (win32Error != NULL) {
            *win32Error = GetLastError();
        }
        CloseHandle(device);
        SecureZeroMemory(&request, sizeof(request));
        return FALSE;
    }

    CloseHandle(device);
    SecureZeroMemory(&request, sizeof(request));
    if (win32Error != NULL) {
        *win32Error = ERROR_SUCCESS;
    }
    return TRUE;
}

static HWND CreateEditBox(HWND parent, int id, const wchar_t *text, int x, int y, int w, int h, DWORD style)
{
    HWND hwnd = CreateWindowExW(WS_EX_CLIENTEDGE,
                                L"EDIT",
                                text,
                                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | style,
                                x,
                                y,
                                w,
                                h,
                                parent,
                                (HMENU)(INT_PTR)id,
                                NULL,
                                NULL);
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)g_Ui.BodyFont, TRUE);
    return hwnd;
}

static HWND CreateButton(HWND parent, int id, const wchar_t *text, int x, int y, int w, int h)
{
    HWND hwnd = CreateWindowExW(0,
                                L"BUTTON",
                                text,
                                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP,
                                x,
                                y,
                                w,
                                h,
                                parent,
                                (HMENU)(INT_PTR)id,
                                NULL,
                                NULL);
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)g_Ui.BodyFont, TRUE);
    return hwnd;
}

static void UpdateStatusUi(void)
{
    DPUSB_STATUS status;
    DWORD error = ERROR_SUCCESS;
    wchar_t message[256];
    wchar_t detail[512];

    if (QueryStatusData(&status, &error)) {
        g_Ui.DriverReady = TRUE;
        g_Ui.SessionOpen = status.SessionOpen != FALSE;
        SetTextBuffer(g_Ui.DriverBadgeText, sizeof(g_Ui.DriverBadgeText) / sizeof(g_Ui.DriverBadgeText[0]), L"Driver Ready");
        SetTextBuffer(g_Ui.ServiceStateText, sizeof(g_Ui.ServiceStateText) / sizeof(g_Ui.ServiceStateText[0]), L"Loaded and responding");
        if (g_Ui.SessionOpen) {
            SetTextBuffer(g_Ui.SessionBadgeText, sizeof(g_Ui.SessionBadgeText) / sizeof(g_Ui.SessionBadgeText[0]), L"Session Unlocked");
            swprintf_s(detail,
                       sizeof(detail) / sizeof(detail[0]),
                       L"Device: %s\r\nAlgorithm: RC4\r\nData offset: %I64u bytes\r\nData length: %I64u bytes",
                       status.DeviceId,
                       status.DataOffsetBytes,
                       status.DataLengthBytes);
        } else {
            SetTextBuffer(g_Ui.SessionBadgeText, sizeof(g_Ui.SessionBadgeText) / sizeof(g_Ui.SessionBadgeText[0]), L"Session Locked");
            swprintf_s(detail, sizeof(detail) / sizeof(detail[0]), L"No secure USB session is currently open.");
        }
        SetTextBuffer(g_Ui.SessionStateText, sizeof(g_Ui.SessionStateText) / sizeof(g_Ui.SessionStateText[0]), detail);
    } else {
        g_Ui.DriverReady = FALSE;
        g_Ui.SessionOpen = FALSE;
        SetTextBuffer(g_Ui.DriverBadgeText, sizeof(g_Ui.DriverBadgeText) / sizeof(g_Ui.DriverBadgeText[0]), L"Driver Offline");
        SetTextBuffer(g_Ui.SessionBadgeText, sizeof(g_Ui.SessionBadgeText) / sizeof(g_Ui.SessionBadgeText[0]), L"Session Locked");

        if (IsExpectedDriverNotLoadedError(error)) {
            swprintf_s(detail,
                       sizeof(detail) / sizeof(detail[0]),
                       L"Waiting for password verification. The USB driver will be loaded from this USB package only after Unlock is pressed.");
        } else {
            FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
            swprintf_s(detail, sizeof(detail) / sizeof(detail[0]), L"Not responding: %s", message);
        }

        SetTextBuffer(g_Ui.ServiceStateText, sizeof(g_Ui.ServiceStateText) / sizeof(g_Ui.ServiceStateText[0]), detail);
        SetTextBuffer(g_Ui.SessionStateText,
                      sizeof(g_Ui.SessionStateText) / sizeof(g_Ui.SessionStateText[0]),
                      L"Enter the initialization password and press Unlock. A wrong password will not load the driver.");
    }

    InvalidateRect(g_Ui.Window, NULL, TRUE);
}

static void RunAutoDriverInitialization(void)
{
    DPUSB_STATUS status;
    DWORD error = ERROR_SUCCESS;
    wchar_t message[512];
    wchar_t servicePath[MAX_PATH + 8];

    ZeroMemory(servicePath, sizeof(servicePath));

    if (QueryStatusData(&status, &error)) {
        AppendLog(L"Driver is already loaded and responding.");
        UpdateStatusUi();
        return;
    }

    if (!IsProcessElevated()) {
        AppendLog(L"Administrator privileges are required; requesting elevation...");
        MessageBoxW(g_Ui.Window,
                    L"Administrator privileges are required. Restart this tool as Administrator, then enter the password again. The driver has not been loaded.",
                    DPUSB_APP_NAME,
                    MB_ICONWARNING | MB_OK);
        UpdateStatusUi();
        return;
    }

    AppendLog(L"Preparing USB package driver...");
    if (!AutoPrepareDriver(g_Ui.DeployedDriverPath,
                           sizeof(g_Ui.DeployedDriverPath) / sizeof(g_Ui.DeployedDriverPath[0]),
                           servicePath,
                           sizeof(servicePath) / sizeof(servicePath[0]),
                           &error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        if (g_Ui.DeployedDriverPath[0] != L'\0') {
            AppendLog(L"Driver file found: %s", g_Ui.DeployedDriverPath);
        }
        if (servicePath[0] != L'\0') {
            AppendLog(L"Driver service ImagePath attempted: %s", servicePath);
        }
        AppendLog(L"Driver initialization failed: %s (Win32=%lu)", message, error);
        UpdateStatusUi();
        return;
    }

    SetTextBuffer(g_Ui.DriverPathText, sizeof(g_Ui.DriverPathText) / sizeof(g_Ui.DriverPathText[0]), g_Ui.DeployedDriverPath);
    AppendLog(L"USB package driver installed and started: %s", g_Ui.DeployedDriverPath);
    if (servicePath[0] != L'\0') {
        AppendLog(L"Driver service ImagePath: %s", servicePath);
    }
    UpdateStatusUi();
}

static void RunUnlockFromUi(void)
{
    wchar_t password[256];
    DPUSB_UNLOCK_WORK_ITEM *workItem;
    HANDLE thread;
    DWORD threadId;

    if (g_Ui.OperationInProgress) {
        AppendLog(L"Another USB operation is already running.");
        return;
    }

    ZeroMemory(password, sizeof(password));
    GetWindowTextW(g_Ui.PasswordEdit, password, sizeof(password) / sizeof(password[0]));
    if (password[0] == L'\0') {
        AppendLog(L"Unlock skipped: password is empty.");
        MessageBoxW(g_Ui.Window, L"Enter the initialization password first.", DPUSB_APP_NAME, MB_ICONWARNING | MB_OK);
        return;
    }

    workItem = (DPUSB_UNLOCK_WORK_ITEM *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(*workItem));
    if (workItem == NULL) {
        AppendLog(L"Unlock failed: insufficient memory.");
        SecureZeroMemory(password, sizeof(password));
        return;
    }

    wcsncpy_s(workItem->Password, sizeof(workItem->Password) / sizeof(workItem->Password[0]), password, _TRUNCATE);
    SecureZeroMemory(password, sizeof(password));
    SetWindowTextSafe(g_Ui.PasswordEdit, L"");
    g_Ui.OperationInProgress = TRUE;
    EnableWindow(g_Ui.UnlockButton, FALSE);
    EnableWindow(g_Ui.RefreshButton, FALSE);
    EnableWindow(g_Ui.LockButton, FALSE);
    SetWindowTextSafe(g_Ui.UnlockButton, L"Unlocking...");
    AppendLog(L"Unlock task started in background.");

    thread = CreateThread(NULL, 0, UnlockWorkerThread, workItem, 0, &threadId);
    if (thread == NULL) {
        LocalFree(workItem);
        g_Ui.OperationInProgress = FALSE;
        EnableWindow(g_Ui.UnlockButton, TRUE);
        EnableWindow(g_Ui.RefreshButton, TRUE);
        EnableWindow(g_Ui.LockButton, TRUE);
        SetWindowTextSafe(g_Ui.UnlockButton, L"Unlock Workspace");
        AppendLog(L"Unlock failed: unable to start worker thread.");
        return;
    }

    CloseHandle(thread);
}

static DWORD WINAPI UnlockWorkerThread(LPVOID parameter)
{
    DPUSB_UNLOCK_WORK_ITEM *workItem = (DPUSB_UNLOCK_WORK_ITEM *)parameter;
    DPUSB_UNLOCK_WORK_RESULT *result;
    wchar_t message[256];
    DPUSB_UNLOCK_SECRET secret;
    DPUSB_PRIVATE_MOUNT mount;
    wchar_t servicePath[MAX_PATH + 8];
    DWORD error = ERROR_SUCCESS;

    result = (DPUSB_UNLOCK_WORK_RESULT *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(*result));
    if (result == NULL) {
        if (workItem != NULL) {
            SecureZeroMemory(workItem, sizeof(*workItem));
            LocalFree(workItem);
        }
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, 0);
        return 1;
    }

    ZeroMemory(&secret, sizeof(secret));
    ZeroMemory(&mount, sizeof(mount));
    ZeroMemory(servicePath, sizeof(servicePath));

    AppendLog(L"Validating USB unlock password...");
    if (workItem == NULL || !UnlockSecretFromPassword(workItem->Password, &secret, &error)) {
        if (workItem != NULL) {
            SecureZeroMemory(workItem, sizeof(*workItem));
            LocalFree(workItem);
        }
        if (error == ERROR_ACCESS_DENIED) {
            AppendLog(L"Unlock denied: password verification failed. Driver was not loaded.");
            PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
            return 0;
        }

        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"USB metadata validation failed: %s", message);
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
        return 0;
    }

    SecureZeroMemory(workItem, sizeof(*workItem));
    LocalFree(workItem);

    if (!IsProcessElevated()) {
        AppendLog(L"Administrator privileges are required. Restart this tool as Administrator. The driver has not been loaded.");
        SecureZeroMemory(&secret, sizeof(secret));
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
        return 0;
    }

    AppendLog(L"Preparing USB package driver...");
    if (!AutoPrepareDriver(result->DeployedDriverPath,
                           sizeof(result->DeployedDriverPath) / sizeof(result->DeployedDriverPath[0]),
                           servicePath,
                           sizeof(servicePath) / sizeof(servicePath[0]),
                           &error)) {

        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        if (result->DeployedDriverPath[0] != L'\0') {
            AppendLog(L"Driver file found: %s", result->DeployedDriverPath);
        }
        if (servicePath[0] != L'\0') {
            AppendLog(L"Driver service ImagePath attempted: %s", servicePath);
        }
        AppendLog(L"Driver initialization failed: %s (Win32=%lu)", message, error);
        SecureZeroMemory(&secret, sizeof(secret));
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
        return 0;
    }

    wcsncpy_s(result->ServicePath, sizeof(result->ServicePath) / sizeof(result->ServicePath[0]), servicePath, _TRUNCATE);
    AppendLog(L"USB package driver installed and started: %s", result->DeployedDriverPath);
    if (servicePath[0] != L'\0') {
        AppendLog(L"Driver service ImagePath: %s", servicePath);
    }

    AppendLog(L"Opening secure USB session for %s...", secret.DeviceId);
    if (!OpenSessionWithSecret(&secret, &error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Unlock failed: %s", message);
        SecureZeroMemory(&secret, sizeof(secret));
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
        return 0;
    }

    if (!MountPrivateWorkspace(&mount, &error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Private workspace mount failed: %s", message);
        CloseSessionData(NULL);
        SecureZeroMemory(&secret, sizeof(secret));
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
        return 0;
    }

    if (!EnsurePrivateWorkspaceFileSystem(&mount, &error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Private workspace file system initialization failed: %s", message);
        UnmountPrivateWorkspace(&mount);
        CloseSessionData(NULL);
        SecureZeroMemory(&secret, sizeof(secret));
        PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
        return 0;
    }

    SecureZeroMemory(&secret, sizeof(secret));
    AppendLog(L"Secure USB session opened. Private workspace mounted at %s", mount.Path);
    wcsncpy_s(result->MountPath, sizeof(result->MountPath) / sizeof(result->MountPath[0]), mount.Path, _TRUNCATE);
    result->Success = TRUE;
    PostMessageW(g_Ui.Window, DPUSB_WM_UNLOCK_DONE, 0, (LPARAM)result);
    return 0;
}

static void CompleteSafeEjectFromWorker(DPUSB_SAFE_EJECT_WORK_RESULT *result)
{
    g_Ui.OperationInProgress = FALSE;
    EnableWindow(g_Ui.UnlockButton, TRUE);
    EnableWindow(g_Ui.RefreshButton, TRUE);
    EnableWindow(g_Ui.LockButton, TRUE);
    EnableWindow(g_Ui.SafeEjectButton, TRUE);
    SetWindowTextSafe(g_Ui.SafeEjectButton, L"Safe Eject");

    if (result == NULL) {
        AppendLog(L"Safe eject failed before returning a result.");
        UpdateStatusUi();
        return;
    }

    if (result->Success) {
        AppendLog(L"%s", result->Message);
        MessageBoxW(g_Ui.Window,
                    result->Message,
                    DPUSB_APP_NAME,
                    MB_ICONINFORMATION | MB_OK);
    } else {
        AppendLog(L"Safe eject failed: %s", result->Message);
        MessageBoxW(g_Ui.Window,
                    result->Message,
                    DPUSB_APP_NAME,
                    MB_ICONWARNING | MB_OK);
    }

    LocalFree(result);
    UpdateStatusUi();
}

static DWORD WINAPI SafeEjectWorkerThread(LPVOID parameter)
{
    DPUSB_SAFE_EJECT_WORK_RESULT *result;
    WCHAR root[MAX_PATH];
    WCHAR message[256];
    DWORD error = ERROR_SUCCESS;
    BOOL ok = TRUE;

    UNREFERENCED_PARAMETER(parameter);

    result = (DPUSB_SAFE_EJECT_WORK_RESULT *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, sizeof(*result));
    if (result == NULL) {
        PostMessageW(g_Ui.Window, DPUSB_WM_SAFE_EJECT_DONE, 0, 0);
        return 1;
    }

    if (!GetUsbSourceRoot(root, sizeof(root) / sizeof(root[0]))) {
        result->Error = ERROR_PATH_NOT_FOUND;
        wcscpy_s(result->Message,
                 sizeof(result->Message) / sizeof(result->Message[0]),
                 L"Could not resolve the public USB tool volume. The device was not ejected.");
        PostMessageW(g_Ui.Window, DPUSB_WM_SAFE_EJECT_DONE, 0, (LPARAM)result);
        return 0;
    }

    wcsncpy_s(result->UsbRoot, sizeof(result->UsbRoot) / sizeof(result->UsbRoot[0]), root, _TRUNCATE);
    AppendLog(L"Safe eject started for %s", root);
    AppendLog(L"Flushing and unmounting the encrypted private workspace...");
    if (!FlushDismountPrivateWorkspace(&error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Private workspace flush/unmount reported: %s", message);
        result->Success = FALSE;
        result->Error = error;
        swprintf_s(result->Message,
                   sizeof(result->Message) / sizeof(result->Message[0]),
                   L"Safe eject stopped because the encrypted private workspace is still in use. Close all files and Explorer windows under the private drive, then try again.");
        PostMessageW(g_Ui.Window, DPUSB_WM_SAFE_EJECT_DONE, 0, (LPARAM)result);
        return 0;
    }

    AppendLog(L"Closing DataProtector USB crypt session...");
    if (!CloseSessionData(&error) && error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Session close reported: %s", message);
        ok = FALSE;
    }

    AppendLog(L"Stopping and unregistering USB crypt runtime driver...");
    if (!StopAndDeleteDriverService(&error) && error != ERROR_SERVICE_DOES_NOT_EXIST) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Driver stop reported: %s", message);
        ok = FALSE;
    }

    AppendLog(L"Flushing and dismounting the public USB tool partition...");
    if (!FlushDismountVolumeByRoot(root, TRUE, &error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Public volume flush/eject reported: %s", message);
        ok = FALSE;
    }

    result->Success = ok;
    result->Error = ok ? ERROR_SUCCESS : error;
    if (ok) {
        swprintf_s(result->Message,
                   sizeof(result->Message) / sizeof(result->Message[0]),
                   L"All DataProtector USB caches were flushed and %s was dismounted. You can safely remove the USB device now.",
                   root);
    } else {
        swprintf_s(result->Message,
                   sizeof(result->Message) / sizeof(result->Message[0]),
                   L"Safe eject could not fully complete for %s. Close any open files or Explorer windows on the USB device, then try again.",
                   root);
    }

    PostMessageW(g_Ui.Window, DPUSB_WM_SAFE_EJECT_DONE, 0, (LPARAM)result);
    return 0;
}

static void CompleteUnlockFromWorker(DPUSB_UNLOCK_WORK_RESULT *result)
{
    g_Ui.OperationInProgress = FALSE;
    EnableWindow(g_Ui.UnlockButton, TRUE);
    EnableWindow(g_Ui.RefreshButton, TRUE);
    EnableWindow(g_Ui.LockButton, TRUE);
    EnableWindow(g_Ui.SafeEjectButton, TRUE);
    SetWindowTextSafe(g_Ui.UnlockButton, L"Unlock Workspace");

    if (result != NULL) {
        if (result->DeployedDriverPath[0] != L'\0') {
            SetTextBuffer(g_Ui.DeployedDriverPath,
                          sizeof(g_Ui.DeployedDriverPath) / sizeof(g_Ui.DeployedDriverPath[0]),
                          result->DeployedDriverPath);
            SetTextBuffer(g_Ui.DriverPathText,
                          sizeof(g_Ui.DriverPathText) / sizeof(g_Ui.DriverPathText[0]),
                          result->DeployedDriverPath);
        }

        if (!result->Success) {
            AppendLog(L"Unlock task finished without opening the private workspace.");
            g_Ui.MountPath[0] = L'\0';
        } else {
            SetTextBuffer(g_Ui.MountPath, sizeof(g_Ui.MountPath) / sizeof(g_Ui.MountPath[0]), result->MountPath);
        }

        LocalFree(result);
    } else {
        AppendLog(L"Unlock task failed before returning a result.");
    }

    UpdateStatusUi();
}

static void RunLockFromUi(void)
{
    DWORD error = ERROR_SUCCESS;
    wchar_t message[256];
    DPUSB_PRIVATE_MOUNT mount;

    AppendLog(L"Closing secure USB session...");
    ZeroMemory(&mount, sizeof(mount));
    (VOID)FlushDismountPrivateWorkspace(NULL);
    UnmountAllPrivateWorkspaces();
    if (!CloseSessionData(&error)) {
        FormatErrorMessage(error, message, sizeof(message) / sizeof(message[0]));
        AppendLog(L"Lock failed: %s", message);
        MessageBoxW(g_Ui.Window, message, DPUSB_APP_NAME, MB_ICONERROR | MB_OK);
        UpdateStatusUi();
        return;
    }

    AppendLog(L"Secure USB session closed.");
    g_Ui.MountPath[0] = L'\0';
    UpdateStatusUi();
}

static void RunSafeEjectFromUi(void)
{
    HANDLE thread;
    DWORD threadId;

    if (g_Ui.OperationInProgress) {
        AppendLog(L"Another USB operation is already running.");
        return;
    }

    g_Ui.OperationInProgress = TRUE;
    EnableWindow(g_Ui.UnlockButton, FALSE);
    EnableWindow(g_Ui.RefreshButton, FALSE);
    EnableWindow(g_Ui.LockButton, FALSE);
    EnableWindow(g_Ui.SafeEjectButton, FALSE);
    SetWindowTextSafe(g_Ui.SafeEjectButton, L"Ejecting...");
    AppendLog(L"Safe eject task started in background.");

    thread = CreateThread(NULL, 0, SafeEjectWorkerThread, NULL, 0, &threadId);
    if (thread == NULL) {
        g_Ui.OperationInProgress = FALSE;
        EnableWindow(g_Ui.UnlockButton, TRUE);
        EnableWindow(g_Ui.RefreshButton, TRUE);
        EnableWindow(g_Ui.LockButton, TRUE);
        EnableWindow(g_Ui.SafeEjectButton, TRUE);
        SetWindowTextSafe(g_Ui.SafeEjectButton, L"Safe Eject");
        AppendLog(L"Safe eject failed: unable to start worker thread.");
        return;
    }

    CloseHandle(thread);
}

static void ShowProvisioningPlan(void)
{
    DPUSB_UNLOCK_MANIFEST manifest;
    wchar_t physicalPath[MAX_PATH];
    wchar_t deviceId[DPUSB_MAX_DEVICE_ID_CHARS];
    wchar_t packageVersion[96];
    wchar_t packageSha256[96];
    wchar_t text[1400];
    DWORD error = ERROR_SUCCESS;

    if (!GetPhysicalDriveForVolume(physicalPath, sizeof(physicalPath) / sizeof(physicalPath[0]), &error)) {
        MessageBoxW(g_Ui.Window,
                    L"The physical USB disk could not be resolved from this tool location.",
                    L"USB Metadata Information",
                    MB_ICONERROR | MB_OK);
        return;
    }

    ZeroMemory(&manifest, sizeof(manifest));
    ZeroMemory(deviceId, sizeof(deviceId));
    ZeroMemory(packageVersion, sizeof(packageVersion));
    ZeroMemory(packageSha256, sizeof(packageSha256));
    if (ReadUnlockManifest(&manifest, &error)) {
        ReadFixedUtf8(manifest.DeviceId, sizeof(manifest.DeviceId), deviceId, sizeof(deviceId) / sizeof(deviceId[0]));
        ReadFixedUtf8(manifest.PackageVersion, sizeof(manifest.PackageVersion), packageVersion, sizeof(packageVersion) / sizeof(packageVersion[0]));
        ReadFixedUtf8(manifest.PackageSha256, sizeof(manifest.PackageSha256), packageSha256, sizeof(packageSha256) / sizeof(packageSha256[0]));
    } else {
        wcscpy_s(deviceId, sizeof(deviceId) / sizeof(deviceId[0]), L"metadata not found or invalid");
        wcscpy_s(packageVersion, sizeof(packageVersion) / sizeof(packageVersion[0]), L"unknown");
        wcscpy_s(packageSha256, sizeof(packageSha256) / sizeof(packageSha256[0]), L"unknown");
    }

    swprintf_s(text,
               sizeof(text) / sizeof(text[0]),
               L"Raw metadata location:\r\n%s @ %I64u\r\n\r\n"
               L"Disk layout:\r\n0-2 MB raw metadata reserve\r\n2-7 MB public tool partition\r\n7 MB+ encrypted data region\r\n\r\n"
               L"Device: %s\r\nRuntime package: %s\r\nSHA256: %s\r\n\r\n"
               L"The endpoint agent writes unlock information into a reserved raw-disk metadata sector. "
               L"No DataProtector key manifest file is required in the public partition. "
               L"The driver is deployed and loaded only after the password validates this raw metadata.",
               physicalPath,
               DPUSB_UNLOCK_METADATA_OFFSET_BYTES,
               deviceId,
               packageVersion,
               packageSha256);

    MessageBoxW(g_Ui.Window,
                text,
                L"USB Metadata Information",
                MB_ICONINFORMATION | MB_OK);
    SecureZeroMemory(&manifest, sizeof(manifest));
}

static void SetRectSize(RECT *rect, int x, int y, int width, int height)
{
    rect->left = x;
    rect->top = y;
    rect->right = x + width;
    rect->bottom = y + height;
}

static int RectWidth(const RECT *rect)
{
    return rect->right - rect->left;
}

static int RectHeight(const RECT *rect)
{
    return rect->bottom - rect->top;
}

static void ComputeLayout(HWND hwnd, DPUSB_UI_LAYOUT *layout)
{
    RECT client;
    int width;
    int height;
    int margin = 28;
    int gap = 18;
    int headerBottom = 104;
    int leftWidth = 332;
    int rightX;
    int rightWidth;
    int contentBottom;

    GetClientRect(hwnd, &client);
    width = RectWidth(&client);
    height = RectHeight(&client);
    contentBottom = height - margin;
    rightX = margin + leftWidth + gap;
    rightWidth = width - rightX - margin;
    if (rightWidth < 548) {
        rightWidth = 548;
    }

    SetRectSize(&layout->DriverCard, margin, headerBottom + 22, leftWidth, 236);
    SetRectSize(&layout->SessionCard, margin, layout->DriverCard.bottom + gap, leftWidth, 172);
    SetRectSize(&layout->ControlCard, rightX, headerBottom + 22, rightWidth, 334);
    SetRectSize(&layout->LogCard,
                rightX,
                layout->ControlCard.bottom + gap,
                rightWidth,
                contentBottom - layout->ControlCard.bottom - gap);

    SetRectSize(&layout->RefreshButton, layout->DriverCard.left + 22, layout->DriverCard.bottom - 58, 110, 36);
    SetRectSize(&layout->PasswordEdit, layout->ControlCard.left + 28, layout->ControlCard.top + 116, rightWidth - 56, 34);
    SetRectSize(&layout->UnlockButton, layout->ControlCard.left + 28, layout->ControlCard.bottom - 58, 168, 38);
    SetRectSize(&layout->LockButton, layout->UnlockButton.right + 12, layout->ControlCard.bottom - 58, 82, 38);
    SetRectSize(&layout->SafeEjectButton, layout->LockButton.right + 12, layout->ControlCard.bottom - 58, 118, 38);
    SetRectSize(&layout->PlanButton, layout->SafeEjectButton.right + 12, layout->ControlCard.bottom - 58, 122, 38);
}

static void MoveControlToRect(HWND hwnd, const RECT *rect)
{
    if (hwnd != NULL) {
        MoveWindow(hwnd, rect->left, rect->top, RectWidth(rect), RectHeight(rect), TRUE);
    }
}

static void LayoutControls(HWND hwnd)
{
    DPUSB_UI_LAYOUT layout;
    RECT logEdit;

    ComputeLayout(hwnd, &layout);
    MoveControlToRect(g_Ui.PasswordEdit, &layout.PasswordEdit);
    MoveControlToRect(g_Ui.RefreshButton, &layout.RefreshButton);
    MoveControlToRect(g_Ui.UnlockButton, &layout.UnlockButton);
    MoveControlToRect(g_Ui.LockButton, &layout.LockButton);
    MoveControlToRect(g_Ui.SafeEjectButton, &layout.SafeEjectButton);
    MoveControlToRect(g_Ui.PlanButton, &layout.PlanButton);

    logEdit = layout.LogCard;
    logEdit.left += 24;
    logEdit.top += 70;
    logEdit.right -= 24;
    logEdit.bottom -= 24;
    if (logEdit.bottom < logEdit.top + 96) {
        logEdit.bottom = logEdit.top + 96;
    }
    MoveControlToRect(g_Ui.LogEdit, &logEdit);
}

static void DrawRoundFill(HDC dc, const RECT *rect, COLORREF fill, COLORREF border, int radius)
{
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);

    RoundRect(dc, rect->left, rect->top, rect->right, rect->bottom, radius, radius);

    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);
}

static void DrawTextBlock(HDC dc,
                          const wchar_t *text,
                          const RECT *rect,
                          HFONT font,
                          COLORREF color,
                          UINT flags)
{
    HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, text, -1, (RECT *)rect, flags);
    SelectObject(dc, oldFont);
}

static void DrawOneLine(HDC dc, const wchar_t *text, int x, int y, int width, int height, HFONT font, COLORREF color)
{
    RECT rect;

    SetRectSize(&rect, x, y, width, height);
    DrawTextBlock(dc, text, &rect, font, color, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void DrawBadge(HDC dc, const wchar_t *text, int x, int y, int width, COLORREF color)
{
    RECT rect;
    RECT textRect;
    COLORREF fill;
    COLORREF border;

    fill = RGB((GetRValue(color) + 255 * 5) / 6, (GetGValue(color) + 255 * 5) / 6, (GetBValue(color) + 255 * 5) / 6);
    border = RGB((GetRValue(color) + 255 * 2) / 3, (GetGValue(color) + 255 * 2) / 3, (GetBValue(color) + 255 * 2) / 3);
    SetRectSize(&rect, x, y, width, 28);
    DrawRoundFill(dc, &rect, fill, border, 14);

    textRect = rect;
    textRect.left += 12;
    textRect.right -= 12;
    DrawTextBlock(dc, text, &textRect, g_Ui.SmallFont, color, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void DrawCardHeader(HDC dc, const RECT *card, const wchar_t *title, const wchar_t *subTitle)
{
    DrawOneLine(dc, title, card->left + 24, card->top + 20, RectWidth(card) - 48, 24, g_Ui.HeaderFont, g_Ui.TextColor);
    DrawOneLine(dc, subTitle, card->left + 24, card->top + 48, RectWidth(card) - 48, 20, g_Ui.SmallFont, g_Ui.MutedColor);
}

static void DrawLabelAndValue(HDC dc,
                              const wchar_t *label,
                              const wchar_t *value,
                              int x,
                              int y,
                              int width,
                              int valueHeight)
{
    RECT valueRect;

    DrawOneLine(dc, label, x, y, width, 18, g_Ui.SmallFont, g_Ui.MutedColor);
    SetRectSize(&valueRect, x, y + 24, width, valueHeight);
    DrawTextBlock(dc,
                  value,
                  &valueRect,
                  g_Ui.BodyFont,
                  g_Ui.TextColor,
                  DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);
}

static void DrawHeader(HDC dc, const RECT *client)
{
    RECT header;
    RECT brandMark;
    RECT line;
    HBRUSH headerBrush;
    HBRUSH lineBrush;

    SetRectSize(&header, 0, 0, RectWidth(client), 104);
    headerBrush = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(dc, &header, headerBrush);
    DeleteObject(headerBrush);

    SetRectSize(&line, 0, 103, RectWidth(client), 1);
    lineBrush = CreateSolidBrush(g_Ui.BorderColor);
    FillRect(dc, &line, lineBrush);
    DeleteObject(lineBrush);

    SetRectSize(&brandMark, 28, 26, 48, 48);
    DrawRoundFill(dc, &brandMark, RGB(37, 99, 235), RGB(37, 99, 235), 12);
    DrawTextBlock(dc, L"DP", &brandMark, g_Ui.HeaderFont, RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    DrawOneLine(dc, L"DataProtector Secure USB", 92, 25, 420, 30, g_Ui.TitleFont, g_Ui.TextColor);
    DrawOneLine(dc, L"Removable media protection and encrypted workspace unlock", 94, 58, 520, 22, g_Ui.BodyFont, g_Ui.MutedColor);

    DrawBadge(dc,
              g_Ui.DriverBadgeText[0] != L'\0' ? g_Ui.DriverBadgeText : L"Driver Offline",
              client->right - 298,
              38,
              132,
              g_Ui.DriverReady ? g_Ui.SuccessColor : g_Ui.DangerColor);
    DrawBadge(dc,
              g_Ui.SessionBadgeText[0] != L'\0' ? g_Ui.SessionBadgeText : L"Session Locked",
              client->right - 154,
              38,
              126,
              g_Ui.SessionOpen ? g_Ui.SuccessColor : g_Ui.DangerColor);
}

static void DrawUi(HDC dc, HWND hwnd)
{
    DPUSB_UI_LAYOUT layout;
    RECT client;
    RECT textRect;

    GetClientRect(hwnd, &client);
    ComputeLayout(hwnd, &layout);
    FillRect(dc, &client, g_Ui.WindowBrush);
    DrawHeader(dc, &client);

    DrawRoundFill(dc, &layout.DriverCard, g_Ui.CardColor, g_Ui.BorderColor, 14);
    DrawCardHeader(dc, &layout.DriverCard, L"Driver Runtime", L"Loaded only after password verification");
    DrawLabelAndValue(dc,
                      L"USB PACKAGE DRIVER",
                      g_Ui.DriverPathText[0] != L'\0' ? g_Ui.DriverPathText : L"DataProtectorUsbRuntime\\driver\\DataProtectorUsbCrypt.sys",
                      layout.DriverCard.left + 24,
                      layout.DriverCard.top + 86,
                      RectWidth(&layout.DriverCard) - 48,
                      42);
    DrawLabelAndValue(dc,
                      L"SERVICE STATE",
                      g_Ui.ServiceStateText[0] != L'\0' ? g_Ui.ServiceStateText : L"Waiting for initialization",
                      layout.DriverCard.left + 24,
                      layout.DriverCard.top + 150,
                      RectWidth(&layout.DriverCard) - 48,
                      34);

    DrawRoundFill(dc, &layout.SessionCard, g_Ui.CardColor, g_Ui.BorderColor, 14);
    DrawCardHeader(dc, &layout.SessionCard, L"Session Status", L"Current unlock state");
    SetRectSize(&textRect,
                layout.SessionCard.left + 24,
                layout.SessionCard.top + 88,
                RectWidth(&layout.SessionCard) - 48,
                RectHeight(&layout.SessionCard) - 108);
    DrawTextBlock(dc,
                  g_Ui.SessionStateText[0] != L'\0' ? g_Ui.SessionStateText : L"Initialize the driver before unlocking protected media.",
                  &textRect,
                  g_Ui.BodyFont,
                  g_Ui.TextColor,
                  DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);

    DrawRoundFill(dc, &layout.ControlCard, g_Ui.CardColor, g_Ui.BorderColor, 14);
    DrawCardHeader(dc, &layout.ControlCard, L"Unlock Workspace", L"Enter the initialization password from the authorized USB package");
    DrawOneLine(dc, L"INITIALIZATION PASSWORD", layout.PasswordEdit.left, layout.PasswordEdit.top - 24, RectWidth(&layout.PasswordEdit), 18, g_Ui.SmallFont, g_Ui.MutedColor);
    SetRectSize(&textRect,
                layout.ControlCard.left + 28,
                layout.PasswordEdit.bottom + 22,
                RectWidth(&layout.ControlCard) - 56,
                84);
    DrawTextBlock(dc,
                  L"This tool reads DataProtector raw-disk metadata from the USB device. The driver is deployed and loaded only after the password validates that metadata.",
                  &textRect,
                  g_Ui.BodyFont,
                  g_Ui.MutedColor,
                  DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);

    DrawRoundFill(dc, &layout.LogCard, g_Ui.CardColor, g_Ui.BorderColor, 14);
    DrawCardHeader(dc, &layout.LogCard, L"Operations Log", L"Local driver deployment and session activity");
}

static void PaintUi(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    HDC memoryDc;
    HBITMAP bitmap;
    HGDIOBJ oldBitmap;
    RECT client;

    GetClientRect(hwnd, &client);
    memoryDc = CreateCompatibleDC(dc);
    bitmap = CreateCompatibleBitmap(dc, RectWidth(&client), RectHeight(&client));
    oldBitmap = SelectObject(memoryDc, bitmap);

    DrawUi(memoryDc, hwnd);
    BitBlt(dc, 0, 0, RectWidth(&client), RectHeight(&client), memoryDc, 0, 0, SRCCOPY);

    SelectObject(memoryDc, oldBitmap);
    DeleteObject(bitmap);
    DeleteDC(memoryDc);
    EndPaint(hwnd, &ps);
}

static BOOL DrawOwnerButton(const DRAWITEMSTRUCT *item)
{
    RECT rect;
    WCHAR text[128];
    BOOL primary;
    BOOL pressed;
    BOOL disabled;
    COLORREF fill;
    COLORREF border;
    COLORREF textColor;

    if (item == NULL || item->CtlType != ODT_BUTTON) {
        return FALSE;
    }

    rect = item->rcItem;
    primary = item->CtlID == DPUSB_ID_UNLOCK;
    pressed = (item->itemState & ODS_SELECTED) != 0;
    disabled = (item->itemState & ODS_DISABLED) != 0;

    if (primary) {
        fill = disabled ? RGB(148, 163, 184) : (pressed ? RGB(29, 78, 216) : g_Ui.AccentColor);
        border = fill;
        textColor = RGB(255, 255, 255);
    } else {
        fill = pressed ? RGB(239, 246, 255) : RGB(255, 255, 255);
        border = RGB(203, 213, 225);
        textColor = disabled ? RGB(148, 163, 184) : g_Ui.TextColor;
    }

    DrawRoundFill(item->hDC, &rect, fill, border, 10);
    GetWindowTextW(item->hwndItem, text, sizeof(text) / sizeof(text[0]));
    DrawTextBlock(item->hDC, text, &rect, g_Ui.BodyFont, textColor, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    if ((item->itemState & ODS_FOCUS) != 0) {
        InflateRect(&rect, -4, -4);
        DrawFocusRect(item->hDC, &rect);
    }

    return TRUE;
}

static LRESULT HandleCtlColor(HDC dc, HWND control)
{
    if (control == g_Ui.PasswordEdit || control == g_Ui.LogEdit) {
        SetTextColor(dc, g_Ui.TextColor);
        SetBkColor(dc, g_Ui.EditColor);
        return (LRESULT)g_Ui.EditBrush;
    }

    SetTextColor(dc, g_Ui.TextColor);
    SetBkColor(dc, g_Ui.WindowColor);
    return (LRESULT)g_Ui.WindowBrush;
}

static BOOL UpdateTrayIcon(BOOL addIcon)
{
    NOTIFYICONDATAW nid;

    if (g_Ui.Window == NULL) {
        return FALSE;
    }

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_Ui.Window;
    nid.uID = DPUSB_TRAY_ICON_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = DPUSB_WM_TRAY;
    nid.hIcon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(DPUSB_ICON_ID));
    wcscpy_s(nid.szTip, sizeof(nid.szTip) / sizeof(nid.szTip[0]), L"DataProtector Secure USB");

    if (addIcon) {
        if (!Shell_NotifyIconW(g_Ui.TrayAdded ? NIM_MODIFY : NIM_ADD, &nid)) {
            if (nid.hIcon != NULL) {
                DestroyIcon(nid.hIcon);
            }
            return FALSE;
        }
        g_Ui.TrayAdded = TRUE;
    } else if (g_Ui.TrayAdded) {
        Shell_NotifyIconW(NIM_DELETE, &nid);
        g_Ui.TrayAdded = FALSE;
    }

    if (nid.hIcon != NULL) {
        DestroyIcon(nid.hIcon);
    }
    return TRUE;
}

static void ShowMainWindowFromTray(void)
{
    if (g_Ui.Window == NULL) {
        return;
    }

    ShowWindow(g_Ui.Window, SW_SHOW);
    ShowWindow(g_Ui.Window, SW_RESTORE);
    SetForegroundWindow(g_Ui.Window);
}

static void ShowTrayMenu(void)
{
    HMENU menu;
    POINT point;
    UINT command;

    menu = CreatePopupMenu();
    if (menu == NULL) {
        return;
    }

    AppendMenuW(menu, MF_STRING, DPUSB_ID_TRAY_SHOW, L"Open");
    AppendMenuW(menu, MF_STRING, DPUSB_ID_SAFE_EJECT, L"Safe Eject");
    AppendMenuW(menu, MF_STRING, DPUSB_ID_LOCK, L"Lock");
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, DPUSB_ID_TRAY_EXIT, L"Exit");

    GetCursorPos(&point);
    SetForegroundWindow(g_Ui.Window);
    command = TrackPopupMenu(menu,
                             TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                             point.x,
                             point.y,
                             0,
                             g_Ui.Window,
                             NULL);
    DestroyMenu(menu);

    if (command != 0) {
        PostMessageW(g_Ui.Window, WM_COMMAND, MAKEWPARAM(command, 0), 0);
    }
}

static void CreateUi(HWND hwnd)
{
    g_Ui.Window = hwnd;
    g_Ui.UiThreadId = GetCurrentThreadId();
    g_Ui.TextColor = RGB(15, 23, 42);
    g_Ui.MutedColor = RGB(100, 116, 139);
    g_Ui.AccentColor = RGB(37, 99, 235);
    g_Ui.SuccessColor = RGB(22, 163, 74);
    g_Ui.DangerColor = RGB(220, 38, 38);
    g_Ui.BorderColor = RGB(226, 232, 240);
    g_Ui.WindowColor = RGB(246, 248, 251);
    g_Ui.CardColor = RGB(255, 255, 255);
    g_Ui.EditColor = RGB(248, 250, 252);
    g_Ui.WindowBrush = CreateSolidBrush(g_Ui.WindowColor);
    g_Ui.CardBrush = CreateSolidBrush(g_Ui.CardColor);
    g_Ui.EditBrush = CreateSolidBrush(g_Ui.EditColor);
    g_Ui.TitleFont = CreateFontW(-25, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_Ui.HeaderFont = CreateFontW(-17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_Ui.BodyFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_Ui.SmallFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

    SetTextBuffer(g_Ui.DriverPathText,
                  sizeof(g_Ui.DriverPathText) / sizeof(g_Ui.DriverPathText[0]),
                  L"DataProtectorUsbRuntime\\driver\\DataProtectorUsbCrypt.sys");
    SetTextBuffer(g_Ui.ServiceStateText, sizeof(g_Ui.ServiceStateText) / sizeof(g_Ui.ServiceStateText[0]), L"Waiting for initialization");
    SetTextBuffer(g_Ui.SessionStateText,
                  sizeof(g_Ui.SessionStateText) / sizeof(g_Ui.SessionStateText[0]),
                  L"Initialize the driver before unlocking protected media.");
    SetTextBuffer(g_Ui.DriverBadgeText, sizeof(g_Ui.DriverBadgeText) / sizeof(g_Ui.DriverBadgeText[0]), L"Driver Offline");
    SetTextBuffer(g_Ui.SessionBadgeText, sizeof(g_Ui.SessionBadgeText) / sizeof(g_Ui.SessionBadgeText[0]), L"Session Locked");

    g_Ui.PasswordEdit = CreateEditBox(hwnd, DPUSB_ID_PASSWORD, L"", 0, 0, 10, 10, ES_PASSWORD);
    g_Ui.RefreshButton = CreateButton(hwnd, DPUSB_ID_REFRESH, L"Refresh", 0, 0, 10, 10);
    g_Ui.UnlockButton = CreateButton(hwnd, DPUSB_ID_UNLOCK, L"Unlock Workspace", 0, 0, 10, 10);
    g_Ui.LockButton = CreateButton(hwnd, DPUSB_ID_LOCK, L"Lock", 0, 0, 10, 10);
    g_Ui.SafeEjectButton = CreateButton(hwnd, DPUSB_ID_SAFE_EJECT, L"Safe Eject", 0, 0, 10, 10);
    g_Ui.PlanButton = CreateButton(hwnd, DPUSB_ID_PLAN, L"Metadata Info", 0, 0, 10, 10);
    g_Ui.LogEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
                                   L"EDIT",
                                   L"",
                                   WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                                   0,
                                   0,
                                   10,
                                   10,
                                   hwnd,
                                   NULL,
                                   NULL,
                                   NULL);
    SendMessageW(g_Ui.LogEdit, WM_SETFONT, (WPARAM)g_Ui.BodyFont, TRUE);
    SendMessageW(g_Ui.PasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)L'*', 0);
    LayoutControls(hwnd);

    if (GetUsbSourceRoot(g_UsbSourceRoot, sizeof(g_UsbSourceRoot) / sizeof(g_UsbSourceRoot[0]))) {
        g_UsbSourceRootSet = TRUE;
        AppendLog(L"UI started. DataProtector USB source detected by Windows API: %s", g_UsbSourceRoot);
    } else {
        AppendLog(L"UI started. Enter the initialization password to unlock this USB workspace.");
    }
    (VOID)UpdateTrayIcon(TRUE);
}

static void DestroyUiResources(void)
{
    (VOID)UpdateTrayIcon(FALSE);
    if (g_Ui.TitleFont != NULL) DeleteObject(g_Ui.TitleFont);
    if (g_Ui.HeaderFont != NULL) DeleteObject(g_Ui.HeaderFont);
    if (g_Ui.BodyFont != NULL) DeleteObject(g_Ui.BodyFont);
    if (g_Ui.SmallFont != NULL) DeleteObject(g_Ui.SmallFont);
    if (g_Ui.WindowBrush != NULL) DeleteObject(g_Ui.WindowBrush);
    if (g_Ui.CardBrush != NULL) DeleteObject(g_Ui.CardBrush);
    if (g_Ui.EditBrush != NULL) DeleteObject(g_Ui.EditBrush);
    ZeroMemory(&g_Ui, sizeof(g_Ui));
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_CREATE:
        CreateUi(hwnd);
        UpdateStatusUi();
        return 0;

    case DPUSB_WM_APPEND_LOG:
        AppendPostedLog((wchar_t *)lParam);
        return 0;

    case DPUSB_WM_UNLOCK_DONE:
        CompleteUnlockFromWorker((DPUSB_UNLOCK_WORK_RESULT *)lParam);
        return 0;

    case DPUSB_WM_SAFE_EJECT_DONE:
        CompleteSafeEjectFromWorker((DPUSB_SAFE_EJECT_WORK_RESULT *)lParam);
        return 0;

    case DPUSB_WM_TRAY:
        if (lParam == WM_LBUTTONDBLCLK) {
            ShowMainWindowFromTray();
            return 0;
        }
        if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
            ShowTrayMenu();
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case DPUSB_ID_REFRESH:
            UpdateStatusUi();
            AppendLog(L"Status refreshed.");
            return 0;
        case DPUSB_ID_UNLOCK:
            RunUnlockFromUi();
            return 0;
        case DPUSB_ID_LOCK:
            RunLockFromUi();
            return 0;
        case DPUSB_ID_SAFE_EJECT:
            RunSafeEjectFromUi();
            return 0;
        case DPUSB_ID_PLAN:
            ShowProvisioningPlan();
            return 0;
        case DPUSB_ID_TRAY_SHOW:
            ShowMainWindowFromTray();
            return 0;
        case DPUSB_ID_TRAY_EXIT:
            DestroyWindow(hwnd);
            return 0;
        default:
            break;
        }
        break;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        return HandleCtlColor((HDC)wParam, (HWND)lParam);

    case WM_DRAWITEM:
        if (DrawOwnerButton((const DRAWITEMSTRUCT *)lParam)) {
            return TRUE;
        }
        break;

    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) {
            ShowWindow(hwnd, SW_HIDE);
            AppendLog(L"Window minimized to tray.");
            return 0;
        }
        LayoutControls(hwnd);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case WM_CLOSE:
        if (g_Ui.OperationInProgress) {
            MessageBoxW(hwnd,
                        L"An unlock or lock operation is still running. Wait until the operation finishes before closing this tool.",
                        DPUSB_APP_NAME,
                        MB_ICONINFORMATION | MB_OK);
            return 0;
        }
        ShowWindow(hwnd, SW_HIDE);
        AppendLog(L"Window hidden. DataProtector Secure USB is still running in the tray.");
        return 0;

    case WM_ERASEBKGND:
    {
        RECT rect;
        GetClientRect(hwnd, &rect);
        FillRect((HDC)wParam, &rect, g_Ui.WindowBrush);
        return 1;
    }

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO *info = (MINMAXINFO *)lParam;
        info->ptMinTrackSize.x = 960;
        info->ptMinTrackSize.y = 680;
        return 0;
    }

    case WM_PAINT:
        PaintUi(hwnd);
        return 0;

    case WM_DESTROY:
        DestroyUiResources();
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

static int RunGui(HINSTANCE instance, int showCommand)
{
    INITCOMMONCONTROLSEX controls;
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg;

    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(DPUSB_ICON_ID));
    wc.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(DPUSB_ICON_ID));
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"DataProtectorUsbToolWindow";

    if (!RegisterClassExW(&wc)) {
        return 1;
    }

    hwnd = CreateWindowExW(0,
                           wc.lpszClassName,
                           DPUSB_APP_NAME,
                           WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT,
                           CW_USEDEFAULT,
                           1060,
                           720,
                           NULL,
                           NULL,
                           instance,
                           NULL);
    if (hwnd == NULL) {
        return 1;
    }

    ShowWindow(hwnd, showCommand);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}

static int DispatchCli(int argc, wchar_t **argv)
{
    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    if (_wcsicmp(argv[1], L"status") == 0) return QueryStatus();
    if (_wcsicmp(argv[1], L"lock") == 0) return Lock();
    if (_wcsicmp(argv[1], L"unlock-password") == 0) return UnlockPassword(argc, argv);

    PrintUsage();
    return 2;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previousInstance, PWSTR commandLine, int showCommand)
{
    wchar_t **argv;
    int argc = 0;
    int result;
    (void)previousInstance;
    (void)commandLine;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        return 1;
    }

    if (argc > 1) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        result = DispatchCli(argc, argv);
        FreeConsole();
    } else {
        if (RelaunchGuiFromLocalCacheIfNeeded(showCommand)) {
            LocalFree(argv);
            return 0;
        }
        result = RunGui(instance, showCommand);
    }

    LocalFree(argv);
    return result;
}
