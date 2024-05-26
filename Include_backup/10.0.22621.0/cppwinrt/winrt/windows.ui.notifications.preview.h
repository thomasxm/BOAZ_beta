// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_Preview_H
#define WINRT_Windows_UI_Notifications_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Notifications.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Notifications.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_Preview_IToastOcclusionManagerPreviewStatics<D>::SetToastWindowMargin(winrt::Windows::UI::WindowId const& appWindowId, double margin) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Preview::IToastOcclusionManagerPreviewStatics)->SetToastWindowMargin(impl::bind_in(appWindowId), margin));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::Preview::IToastOcclusionManagerPreviewStatics> : produce_base<D, winrt::Windows::UI::Notifications::Preview::IToastOcclusionManagerPreviewStatics>
    {
        int32_t __stdcall SetToastWindowMargin(struct struct_Windows_UI_WindowId appWindowId, double margin) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetToastWindowMargin(*reinterpret_cast<winrt::Windows::UI::WindowId const*>(&appWindowId), margin);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Preview
{
    inline auto ToastOcclusionManagerPreview::SetToastWindowMargin(winrt::Windows::UI::WindowId const& appWindowId, double margin)
    {
        impl::call_factory<ToastOcclusionManagerPreview, IToastOcclusionManagerPreviewStatics>([&](IToastOcclusionManagerPreviewStatics const& f) { return f.SetToastWindowMargin(appWindowId, margin); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Notifications::Preview::IToastOcclusionManagerPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::Preview::ToastOcclusionManagerPreview> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
