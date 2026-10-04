#include "pch.h"
#include "Kernel_Hooks.h"

#include "Gdi32_Hooks.h"
#include "Streamline_Hooks.h"
#include "LibraryLoad_Hooks.h"

#include <fsr4/FSR4Upgrade.h>
#include <fsr4/FSR4ModelSelection.h>
#include <proxies/NVNGX_Proxy.h>

#include <Util.h>
#include <State.h>
#include <Config.h>

#include <cwctype>

#include "Hook_Utils.h"

#pragma intrinsic(_ReturnAddress)

static inline void NormalizePath(std::string& path)
{
    while (!path.empty() && (path.back() == '\\' || path.back() == '/'))
        path.pop_back();
}

static inline bool IsInsideWindowsDirectory(const std::string& path)
{
    char windowsDir[MAX_PATH];
    UINT len = GetWindowsDirectoryA(windowsDir, MAX_PATH);

    if (len == 0 || len >= MAX_PATH)
        return false;

    std::string pathToCheck(path);
    std::string windowsPath(windowsDir);

    NormalizePath(pathToCheck);
    NormalizePath(windowsPath);

    to_lower_in_place(pathToCheck);
    to_lower_in_place(windowsPath);

    // Check if pathToCheck starts with windowsPath, while having a slash after that
    if (pathToCheck.compare(0, windowsPath.size(), windowsPath) == 0 &&
        (pathToCheck.size() == windowsPath.size() || pathToCheck[windowsPath.size()] == '\\' ||
         pathToCheck[windowsPath.size()] == '/'))
        return true;

    return false;
}

static inline HMODULE CheckLoad(const std::wstring& name)
{
    do
    {
        if (State::Instance().isShuttingDown || LibraryLoadHooks::IsApiSetName(name))
            break;

        if (State::SkipDllChecks())
        {
            const std::wstring skip = string_to_wstring(State::SkipDllName());

            if (skip.empty() || LibraryLoadHooks::EndsWithInsensitive(name, std::wstring_view(skip)) ||
                LibraryLoadHooks::EndsWithInsensitive(name, std::wstring(skip + L".dll")))
            {
                LOG_TRACE("Skip checks for: {}", wstring_to_string(name.data()));
                break;
            }
        }

        auto moduleHandle = LibraryLoadHooks::LoadLibraryCheckW(name.data(), name.data());

        // skip loading of dll
        if (moduleHandle == (HMODULE) 1337)
            break;

        if (moduleHandle != nullptr)
        {
            LOG_TRACE("{}, caller: {}", wstring_to_string(name.data()), Util::WhoIsTheCaller(_ReturnAddress()));
            return moduleHandle;
        }
    } while (false);

    return nullptr;
}

// sl.common resolves NVSDK_NGX_D3D12_CreateFeature itself. Witcher never calls
// slAllocateResources. Redirect only this export, and only after the name matches,
// so the rest of GetProcAddress stays on the fast path (a blanket redirect black-screened).
extern "C" NVSDK_NGX_Result MetalFx_D3D12_CreateFeature_Forward(ID3D12GraphicsCommandList* InCmdList,
                                                                   NVSDK_NGX_Feature InFeatureID,
                                                                   NVSDK_NGX_Parameter* InParameters,
                                                                   NVSDK_NGX_Handle** OutHandle);
extern "C" NVSDK_NGX_Result MetalFx_D3D12_EvaluateFeature_Forward(ID3D12GraphicsCommandList* InCmdList,
                                                                  const NVSDK_NGX_Handle* InFeatureHandle,
                                                                  NVSDK_NGX_Parameter* InParameters,
                                                                  PFN_NVSDK_NGX_ProgressCallback InCallback);
extern "C" NVSDK_NGX_Result MetalFx_D3D12_GetFeatureRequirements_Forward(
    IDXGIAdapter* Adapter, const NVSDK_NGX_FeatureDiscoveryInfo* FeatureDiscoveryInfo,
    NVSDK_NGX_FeatureRequirement* OutSupported);

using PFN_MetalFxEvaluate = NVSDK_NGX_Result (*)(ID3D12GraphicsCommandList*, const NVSDK_NGX_Handle*,
                                                 NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
using PFN_MetalFxRequirements = NVSDK_NGX_Result (*)(IDXGIAdapter*, const NVSDK_NGX_FeatureDiscoveryInfo*,
                                                     NVSDK_NGX_FeatureRequirement*);
extern "C" PFN_MetalFxEvaluate g_MetalFx_Real_D3D12_EvaluateFeature;
extern "C" PFN_MetalFxRequirements g_MetalFx_Real_D3D12_GetFeatureRequirements;

static FARPROC MetalFxCreateFeatureFromGetProcAddress(HMODULE hModule, LPCSTR lpProcName, FARPROC real)
{
    static bool logged = false;
    if (!logged)
    {
        logged = true;
        LOG_INFO("MetalFX: GetProcAddress NVSDK_NGX_D3D12_CreateFeature module {0:X} real {1:X}",
                 (uint64_t) hModule, (uint64_t) real);
    }

    // Opti's own export already forwards to D3DMetal. Replacing it would recurse
    // if LoadLibrary("nvngx.dll") returned this dll.
    if (real == nullptr || hModule == dllModule)
        return real;

    static bool installed = false;
    if (!installed)
    {
        installed = true;
        LOG_INFO("MetalFX: installed NVSDK_NGX_D3D12_CreateFeature forwarder (calling thread, D3DMetal nvngx)");
    }
    return (FARPROC) &MetalFx_D3D12_CreateFeature_Forward;
}

static bool NameIsNvngxCore(const wchar_t* name)
{
    if (name == nullptr)
        return false;
    std::wstring lower(name);
    for (auto& c : lower)
        c = (wchar_t) towlower(c);
    if (lower.find(L"nvngx_") != std::wstring::npos)
        return false;
    return lower.find(L"nvngx.dll") != std::wstring::npos;
}

static void HookLoadedNvngx(HMODULE module, const wchar_t* name)
{
    if (!NameIsNvngxCore(name) || module == nullptr || module == dllModule)
        return;
    if (!Config::Instance()->NgxDlssPassthrough())
        return;
    LOG_INFO("MetalFX: nvngx core loaded ({0:X}), hooking GetFeatureRequirements", (uint64_t) module);
    HookNgxApi(module);
}

static FARPROC MaybeRedirectCreateFeature(HMODULE hModule, LPCSTR lpProcName,
                                          FARPROC(WINAPI* original)(HMODULE, LPCSTR))
{
    if (lpProcName == nullptr)
        return nullptr;

    if (strcmp(lpProcName, "NVSDK_NGX_D3D12_CreateFeature") == 0)
    {
        auto real = original(hModule, lpProcName);
        return MetalFxCreateFeatureFromGetProcAddress(hModule, lpProcName, real);
    }

    if (strcmp(lpProcName, "NVSDK_NGX_D3D12_EvaluateFeature") == 0)
    {
        auto real = original(hModule, lpProcName);
        if (real == nullptr || hModule == dllModule)
            return real;
        g_MetalFx_Real_D3D12_EvaluateFeature = (PFN_MetalFxEvaluate) real;
        static bool logged = false;
        if (!logged)
        {
            logged = true;
            LOG_INFO("MetalFX: installed NVSDK_NGX_D3D12_EvaluateFeature forwarder real {0:X}", (uint64_t) real);
        }
        return (FARPROC) &MetalFx_D3D12_EvaluateFeature_Forward;
    }

    if (strcmp(lpProcName, "NVSDK_NGX_D3D12_GetFeatureRequirements") == 0)
    {
        auto real = original(hModule, lpProcName);
        if (real == nullptr || hModule == dllModule)
            return real;
        if (Config::Instance()->NgxDlssPassthrough())
            HookNgxApi(hModule);
        g_MetalFx_Real_D3D12_GetFeatureRequirements = (PFN_MetalFxRequirements) real;
        static bool logged = false;
        if (!logged)
        {
            logged = true;
            LOG_INFO("MetalFX: installed NVSDK_NGX_D3D12_GetFeatureRequirements forwarder real {0:X}", (uint64_t) real);
        }
        return (FARPROC) &MetalFx_D3D12_GetFeatureRequirements_Forward;
    }

    return nullptr;
}

VALIDATE_HOOK(hk_K32_GetProcAddress, Kernel32Proxy::PFN_GetProcAddress)
FARPROC WINAPI KernelHooks::hk_K32_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{

    if ((size_t) lpProcName < 0x000000000000F000)
    {
        if (hModule == dllModule)
            LOG_TRACE("Ordinal call: {:X}", (size_t) lpProcName);

        return o_K32_GetProcAddress(hModule, lpProcName);
    }

    if (lpProcName != nullptr)
    {
        auto redirected = MaybeRedirectCreateFeature(hModule, lpProcName, o_K32_GetProcAddress);
        if (redirected != nullptr || strcmp(lpProcName, "NVSDK_NGX_D3D12_CreateFeature") == 0 ||
            strcmp(lpProcName, "NVSDK_NGX_D3D12_EvaluateFeature") == 0 ||
            strcmp(lpProcName, "NVSDK_NGX_D3D12_GetFeatureRequirements") == 0)
            return redirected;
    }

    // if (hModule == dllModule && lpProcName != nullptr)
    //{
    //     LOG_TRACE("Trying to get process address of {}, caller: {}", lpProcName,
    //               Util::WhoIsTheCaller(_ReturnAddress()));
    // }

    // FSR 4 Init in case of missing amdxc64.dll
    // 2nd check is amdxcffx64.dll trying to queue amdxc64 but amdxc64 not being loaded.
    // Also skip the internal call of amdxc64
    if (lpProcName != nullptr && (hModule == amdxc64Mark || hModule == nullptr) &&
        lstrcmpA(lpProcName, "AmdExtD3DCreateInterface") == 0 && Config::Instance()->Fsr4Update.value_or_default() &&
        Util::GetCallerModule(_ReturnAddress()) != KernelBaseProxy::GetModuleHandleW_()(L"amdxc64.dll"))
    {
        return (FARPROC) &hkAmdExtD3DCreateInterface;
    }

    return o_K32_GetProcAddress(hModule, lpProcName);
}

VALIDATE_HOOK(hk_K32_GetModuleHandleA, Kernel32Proxy::PFN_GetModuleHandleA)
HMODULE WINAPI KernelHooks::hk_K32_GetModuleHandleA(LPCSTR lpModuleName)
{
    if (lpModuleName != NULL)
    {
        if (strcmp(lpModuleName, "nvngx_dlssg.dll") == 0)
        {
            LOG_TRACE("Trying to get module handle of {}, caller: {}", lpModuleName,
                      Util::WhoIsTheCaller(_ReturnAddress()));
            return dllModule;
        }
        else if (strcmp(lpModuleName, "amdxc64.dll") == 0)
        {
            // Libraries like FFX SDK or AntiLag 2 SDK do not load amdxc64 themselves
            // so most likely amdxc64 is getting loaded by the driver itself.
            // Therefore it should be safe for us to return a custom implementation when it's not loaded
            // This can get removed if Proton starts to ship amdxc64

            CheckForGPU();

            auto original = o_K32_GetModuleHandleA(lpModuleName);

            if (original == nullptr && Config::Instance()->Fsr4Update.value_or_default())
            {
                LOG_INFO("amdxc64.dll is not loaded, giving a fake HMODULE");
                return amdxc64Mark;
            }

            return original;
        }
    }

    return o_K32_GetModuleHandleA(lpModuleName);
}

VALIDATE_HOOK(hk_K32_GetModuleHandleExW, Kernel32Proxy::PFN_GetModuleHandleExW)
BOOL WINAPI KernelHooks::hk_K32_GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)
{
    if (lpModuleName && dwFlags == GET_MODULE_HANDLE_EX_FLAG_PIN && lstrcmpW(L"nvapi64.dll", lpModuleName) == 0 &&
        phModule)
    {
        LOG_TRACE("Suspected SpecialK call for nvapi64");
        *phModule = LibraryLoadHooks::LoadNvApi();
        return true;
    }

    return o_K32_GetModuleHandleExW(dwFlags, lpModuleName, phModule);
}

VALIDATE_HOOK(hk_KB_GetProcAddress, KernelBaseProxy::PFN_GetProcAddress)
FARPROC WINAPI KernelHooks::hk_KB_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if ((size_t) lpProcName < 0x000000000000F000)
    {
        if (hModule == dllModule)
            LOG_TRACE("Ordinal call: {:X}", (size_t) lpProcName);

        return o_KB_GetProcAddress(hModule, lpProcName);
    }

    if (lpProcName != nullptr)
    {
        auto redirected = MaybeRedirectCreateFeature(hModule, lpProcName, o_KB_GetProcAddress);
        if (redirected != nullptr || strcmp(lpProcName, "NVSDK_NGX_D3D12_CreateFeature") == 0 ||
            strcmp(lpProcName, "NVSDK_NGX_D3D12_EvaluateFeature") == 0 ||
            strcmp(lpProcName, "NVSDK_NGX_D3D12_GetFeatureRequirements") == 0)
            return redirected;
    }

    // if (hModule == dllModule && lpProcName != nullptr)
    //{
    //     LOG_TRACE("Trying to get process address of {}, caller: {}", lpProcName,
    //               Util::WhoIsTheCaller(_ReturnAddress()));
    // }

    return o_KB_GetProcAddress(hModule, lpProcName);
}

VALIDATE_HOOK(hk_K32_GetFileAttributesW, Kernel32Proxy::PFN_GetFileAttributesW)
DWORD WINAPI KernelHooks::hk_K32_GetFileAttributesW(LPCWSTR lpFileName)
{
    if (!State::Instance().nvngxExists && State::Instance().nvngxReplacement.has_value() &&
        (Config::Instance()->DxgiSpoofing.value_or_default() ||
         Config::Instance()->StreamlineSpoofing.value_or_default()))
    {
        auto path = wstring_to_string(std::wstring(lpFileName));
        to_lower_in_place(path);

        if (path.contains("nvngx.dll") && !path.contains("_nvngx.dll") &&
            !IsInsideWindowsDirectory(path)) // apply the override to just one path
        {
            LOG_DEBUG("Overriding GetFileAttributesW for nvngx");
            return FILE_ATTRIBUTE_ARCHIVE;
        }
    }

    return o_K32_GetFileAttributesW(lpFileName);
}

VALIDATE_HOOK(hk_K32_CreateFileW, Kernel32Proxy::PFN_CreateFileW)
HANDLE WINAPI KernelHooks::hk_K32_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                              LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                              DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (!State::Instance().nvngxExists && State::Instance().nvngxReplacement.has_value() &&
        (Config::Instance()->DxgiSpoofing.value_or_default() ||
         Config::Instance()->StreamlineSpoofing.value_or_default()))
    {
        auto path = wstring_to_string(std::wstring(lpFileName));
        to_lower_in_place(path);

        static auto signedDll = Util::FindFilePath(Util::ExePath().remove_filename(), "nvngx_dlss.dll");

        if (path.contains("nvngx.dll") && !path.contains("_nvngx.dll") && // apply the override to just one path
            !IsInsideWindowsDirectory(path) && signedDll.has_value())
        {
            LOG_DEBUG("Overriding CreateFileW for nvngx with a signed dll, original path: {}", path);
            return o_K32_CreateFileW(signedDll.value().c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                     dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }
    }

    return o_K32_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                             dwFlagsAndAttributes, hTemplateFile);
}

VALIDATE_HOOK(hk_K32_OutputDebugStringW, Kernel32Proxy::PFN_OutputDebugStringW)
VOID WINAPI KernelHooks::hk_K32_OutputDebugStringW(LPCWSTR lpOutputString)
{
    o_K32_OutputDebugStringW(lpOutputString);

    std::wstring result(lpOutputString);

    while (!result.empty() && (result.back() == L'\n' || result.back() == L'\r'))
    {
        result.pop_back();
    }

    LOG_TRACE(L"{}", result);
}

VALIDATE_HOOK(hk_K32_OutputDebugStringA, Kernel32Proxy::PFN_OutputDebugStringA)
VOID WINAPI KernelHooks::hk_K32_OutputDebugStringA(LPCSTR lpOutputString)
{
    o_K32_OutputDebugStringA(lpOutputString);

    std::string result(lpOutputString);

    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
    {
        result.pop_back();
    }

    LOG_TRACE("{}", result);
}

// Load Library checks

VALIDATE_HOOK(hk_K32_LoadLibraryW, Kernel32Proxy::PFN_LoadLibraryW)
HMODULE KernelHooks::hk_K32_LoadLibraryW(LPCWSTR lpLibFileName)
{
    if (lpLibFileName == nullptr)
        return NULL;

    std::wstring name(lpLibFileName);

#ifdef _DEBUG
    // LOG_TRACE("{}, caller: {}", wstring_to_string(name.data()), Util::WhoIsTheCaller(_ReturnAddress()));
#endif

    auto result = CheckLoad(name);

    if (result != nullptr)
        return result;

    auto loaded = o_K32_LoadLibraryW(lpLibFileName);
    HookLoadedNvngx(loaded, lpLibFileName);
    return loaded;
}

VALIDATE_HOOK(hk_K32_LoadLibraryA, Kernel32Proxy::PFN_LoadLibraryA)
HMODULE KernelHooks::hk_K32_LoadLibraryA(LPCSTR lpLibFileName)
{
    if (lpLibFileName == nullptr)
        return NULL;

    std::string nameA(lpLibFileName);
    std::wstring name = string_to_wstring(nameA);

#ifdef _DEBUG
    // LOG_TRACE("{}, caller: {}", nameA.data(), Util::WhoIsTheCaller(_ReturnAddress()));
#endif

    auto result = CheckLoad(name);

    if (result != nullptr)
        return result;

    auto loaded = o_K32_LoadLibraryA(lpLibFileName);
    HookLoadedNvngx(loaded, name.c_str());
    return loaded;
}

VALIDATE_HOOK(hk_K32_LoadLibraryExW, Kernel32Proxy::PFN_LoadLibraryExW)
HMODULE KernelHooks::hk_K32_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    if (lpLibFileName == nullptr)
        return NULL;

    std::wstring name(lpLibFileName);

#ifdef _DEBUG
    // LOG_TRACE("{}, caller: {}", wstring_to_string(name.data()), Util::WhoIsTheCaller(_ReturnAddress()));
#endif

    auto result = CheckLoad(name);

    if (result != nullptr)
        return result;

    auto loaded = o_K32_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    HookLoadedNvngx(loaded, lpLibFileName);
    return loaded;
}

VALIDATE_HOOK(hk_K32_LoadLibraryExA, Kernel32Proxy::PFN_LoadLibraryExA)
HMODULE KernelHooks::hk_K32_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    if (lpLibFileName == nullptr)
        return NULL;

    std::string nameA(lpLibFileName);
    std::wstring name = string_to_wstring(nameA);

#ifdef _DEBUG
    // LOG_TRACE("{}, caller: {}", nameA.data(), Util::WhoIsTheCaller(_ReturnAddress()));
#endif

    auto result = CheckLoad(name);

    if (result != nullptr)
        return result;

    auto loaded = o_K32_LoadLibraryExA(lpLibFileName, hFile, dwFlags);
    HookLoadedNvngx(loaded, name.c_str());
    return loaded;
}

VALIDATE_HOOK(hk_KB_LoadLibraryExW, KernelBaseProxy::PFN_LoadLibraryExW)
HMODULE KernelHooks::hk_KB_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    if (lpLibFileName == nullptr)
        return NULL;

    std::wstring name(lpLibFileName);

#ifdef _DEBUG
    // LOG_TRACE("{}, caller: {}", wstring_to_string(name.data()), Util::WhoIsTheCaller(_ReturnAddress()));
#endif

    auto result = CheckLoad(name);

    if (result != nullptr)
        return result;

    auto loaded = o_KB_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    HookLoadedNvngx(loaded, lpLibFileName);
    return loaded;
}

VALIDATE_HOOK(hk_K32_FreeLibrary, Kernel32Proxy::PFN_FreeLibrary)
BOOL KernelHooks::hk_K32_FreeLibrary(HMODULE lpLibrary)
{
    if (lpLibrary == nullptr)
        return STATUS_INVALID_PARAMETER;

#ifdef _DEBUG
    // LOG_TRACE("{:X}", (size_t) lpLibrary);
#endif

    if (!State::Instance().isShuttingDown)
    {
        auto result = LibraryLoadHooks::FreeLibrary(lpLibrary);

        if (result.has_value())
            return result.value() == TRUE;
    }

    return o_K32_FreeLibrary(lpLibrary);
}
