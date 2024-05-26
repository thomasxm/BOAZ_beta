// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WindowManagement_Preview_H
#define WINRT_Windows_UI_WindowManagement_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.WindowManagement.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_Preview_IWindowManagementPreviewStatics<D>::SetPreferredMinSize(winrt::Windows::UI::WindowManagement::AppWindow const& window, winrt::Windows::Foundation::Size const& preferredFrameMinSize) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics)->SetPreferredMinSize(*(void**)(&window), impl::bind_in(preferredFrameMinSize)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreview> : produce_base<D, winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreview>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics> : produce_base<D, winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>
    {
        int32_t __stdcall SetPreferredMinSize(void* window, winrt::Windows::Foundation::Size preferredFrameMinSize) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPreferredMinSize(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindow const*>(&window), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&preferredFrameMinSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement::Preview
{
    inline auto WindowManagementPreview::SetPreferredMinSize(winrt::Windows::UI::WindowManagement::AppWindow const& window, winrt::Windows::Foundation::Size const& preferredFrameMinSize)
    {
        impl::call_factory<WindowManagementPreview, IWindowManagementPreviewStatics>([&](IWindowManagementPreviewStatics const& f) { return f.SetPreferredMinSize(window, preferredFrameMinSize); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::Preview::WindowManagementPreview> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
