#include <Windows.h>
#include <tchar.h>

int isPE(PTSTR);

int main()
{
    TCHAR fileName[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, fileName, MAX_PATH);
    int r = isPE(fileName);
    if (r < 0)
    {
        _tprintf(_T("Got error with %s\n"), fileName);
    }
    else if (r == 1)
    {
        _tprintf(_T("%s is PE file\n"), fileName);
    }
    else
    {
        _tprintf(_T("%s is not PE file\n"), fileName);
    }
}

int isPE(PTSTR fileName)
{
    HANDLE file = CreateFile(
        fileName,
        GENERIC_READ,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        _tprintf(_T("file handle error code: %d\n"), GetLastError());
        return -1;
    }
    __int32 signatureLocation = 0;
    const unsigned int signatureOffset = 0x3C;
    const DWORD offsetSize = 4;
    const DWORD signatureSize = 4;
    DWORD read = 0;
    DWORD ret = 0;
    ret = SetFilePointer(file, signatureOffset, NULL, FILE_BEGIN);
    if (ret == INVALID_SET_FILE_POINTER)
    {
        CloseHandle(file);
        _tprintf(_T("SetFilePointer error code: %d\n"), GetLastError());
        return -1;
    }
    ReadFile(file, &signatureLocation, offsetSize, &read, NULL);
    if (read != 4)
    {
        CloseHandle(file);
        _tprintf(_T("ReadFile error code: %d\n"), GetLastError());
        return -1;
    }
    ret = SetFilePointer(file, signatureLocation, NULL, FILE_BEGIN);
    if (ret == INVALID_SET_FILE_POINTER)
    {
        CloseHandle(file);
        _tprintf(_T("SetFilePointer error code: %d\n"), GetLastError());
        return -1;
    }
    read = 0;
    __int32 signature = 0;
    ReadFile(file, &signature, signatureSize, &read, NULL);
    if (read != 4)
    {
        CloseHandle(file);
        _tprintf(_T("ReadFile error code: %d\n"), GetLastError());
        return -1;
    }
    CloseHandle(file);
    return signature == 0x4550;
}
