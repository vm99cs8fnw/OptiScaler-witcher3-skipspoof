#pragma once

#include "SysUtils.h"

#include <dxgi1_6.h>

class DxgiSpoofing
{
  public:
    static void AttachToAdapter(IUnknown* unkAdapter);
    // Unspoofed GetDesc via original vtable hook (for Intel/RDNA detect).
    static HRESULT GetRealAdapterDesc(IDXGIAdapter* adapter, DXGI_ADAPTER_DESC* pDesc);

  private:
    static HRESULT hkGetDesc(IDXGIAdapter* This, DXGI_ADAPTER_DESC* pDesc);
    static HRESULT hkGetDesc1(IDXGIAdapter1* This, DXGI_ADAPTER_DESC1* pDesc);
    static HRESULT hkGetDesc2(IDXGIAdapter2* This, DXGI_ADAPTER_DESC2* pDesc);
    static HRESULT hkGetDesc3(IDXGIAdapter4* This, DXGI_ADAPTER_DESC3* pDesc);
};
