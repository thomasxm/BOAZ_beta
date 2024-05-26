// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Display_H
#define WINRT_Windows_System_Display_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.System.Display.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Display_IDisplayRequest<D>::RequestActive() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Display::IDisplayRequest)->RequestActive());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Display_IDisplayRequest<D>::RequestRelease() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Display::IDisplayRequest)->RequestRelease());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Display::IDisplayRequest> : produce_base<D, winrt::Windows::System::Display::IDisplayRequest>
    {
        int32_t __stdcall RequestActive() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestActive();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestRelease() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestRelease();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Display
{
    inline DisplayRequest::DisplayRequest() :
        DisplayRequest(impl::call_factory_cast<DisplayRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), DisplayRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DisplayRequest>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Display::IDisplayRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Display::DisplayRequest> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
