// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Effects_H
#define WINRT_Windows_Graphics_Effects_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Graphics.h"
#include "winrt/impl/Windows.Graphics.Effects.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Effects_IGraphicsEffect<D>::Name() const
    {
        void* name{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Effects::IGraphicsEffect)->get_Name(&name));
        return hstring{ name, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Effects_IGraphicsEffect<D>::Name(param::hstring const& name) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Effects::IGraphicsEffect)->put_Name(*(void**)(&name)));
    }
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Effects::IGraphicsEffect> : produce_base<D, winrt::Windows::Graphics::Effects::IGraphicsEffect>
    {
        int32_t __stdcall get_Name(void** name) noexcept final try
        {
            clear_abi(name);
            typename D::abi_guard guard(this->shim());
            *name = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* name) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Effects::IGraphicsEffectSource> : produce_base<D, winrt::Windows::Graphics::Effects::IGraphicsEffectSource>
    {
    };
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Effects
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Graphics::Effects::IGraphicsEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Effects::IGraphicsEffectSource> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
