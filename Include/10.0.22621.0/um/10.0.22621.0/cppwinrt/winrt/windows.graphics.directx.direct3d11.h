// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_DirectX_Direct3D11_H
#define WINRT_Windows_Graphics_DirectX_Direct3D11_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Graphics.DirectX.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_DirectX_Direct3D11_IDirect3DDevice<D>::Trim() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice)->Trim());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DSurfaceDescription) consume_Windows_Graphics_DirectX_Direct3D11_IDirect3DSurface<D>::Description() const
    {
        winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DSurfaceDescription value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface)->get_Description(put_abi(value)));
        return value;
    }
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice> : produce_base<D, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>
    {
        int32_t __stdcall Trim() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Trim();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface> : produce_base<D, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>
    {
        int32_t __stdcall get_Description(struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DSurfaceDescription* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DSurfaceDescription>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DSurfaceDescription>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11
{
    constexpr auto operator|(Direct3DBindings const left, Direct3DBindings const right) noexcept
    {
        return static_cast<Direct3DBindings>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(Direct3DBindings& left, Direct3DBindings const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(Direct3DBindings const left, Direct3DBindings const right) noexcept
    {
        return static_cast<Direct3DBindings>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(Direct3DBindings& left, Direct3DBindings const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(Direct3DBindings const value) noexcept
    {
        return static_cast<Direct3DBindings>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(Direct3DBindings const left, Direct3DBindings const right) noexcept
    {
        return static_cast<Direct3DBindings>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(Direct3DBindings& left, Direct3DBindings const right) noexcept
    {
        left = left ^ right;
        return left;
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
