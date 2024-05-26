// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_H
#define WINRT_Windows_System_RemoteDesktop_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.System.RemoteDesktop.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteDesktop_IInteractiveSessionStatics<D>::IsRemote() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::IInteractiveSessionStatics)->get_IsRemote(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::IInteractiveSessionStatics> : produce_base<D, winrt::Windows::System::RemoteDesktop::IInteractiveSessionStatics>
    {
        int32_t __stdcall get_IsRemote(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRemote());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop
{
    inline auto InteractiveSession::IsRemote()
    {
        return impl::call_factory_cast<bool(*)(IInteractiveSessionStatics const&), InteractiveSession, IInteractiveSessionStatics>([](IInteractiveSessionStatics const& f) { return f.IsRemote(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::RemoteDesktop::IInteractiveSessionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::InteractiveSession> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
