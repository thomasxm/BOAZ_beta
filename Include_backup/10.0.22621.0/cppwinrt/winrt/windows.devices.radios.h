// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Radios_H
#define WINRT_Windows_Devices_Radios_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Radios.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>) consume_Windows_Devices_Radios_IRadio<D>::SetStateAsync(winrt::Windows::Devices::Radios::RadioState const& value) const
    {
        void* retval{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadio)->SetStateAsync(static_cast<int32_t>(value), &retval));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>{ retval, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Radios_IRadio<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Radios::Radio, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadio)->add_StateChanged(*(void**)(&handler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Devices_Radios_IRadio<D>::StateChanged_revoker consume_Windows_Devices_Radios_IRadio<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Radios::Radio, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Radios_IRadio<D>::StateChanged(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadio)->remove_StateChanged(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Radios::RadioState) consume_Windows_Devices_Radios_IRadio<D>::State() const
    {
        winrt::Windows::Devices::Radios::RadioState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadio)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Radios_IRadio<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadio)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Radios::RadioKind) consume_Windows_Devices_Radios_IRadio<D>::Kind() const
    {
        winrt::Windows::Devices::Radios::RadioKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadio)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Radios::Radio>>) consume_Windows_Devices_Radios_IRadioStatics<D>::GetRadiosAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadioStatics)->GetRadiosAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Radios::Radio>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Radios_IRadioStatics<D>::GetDeviceSelector() const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadioStatics)->GetDeviceSelector(&deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>) consume_Windows_Devices_Radios_IRadioStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadioStatics)->FromIdAsync(*(void**)(&deviceId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>) consume_Windows_Devices_Radios_IRadioStatics<D>::RequestAccessAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Radios::IRadioStatics)->RequestAccessAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Radios::IRadio> : produce_base<D, winrt::Windows::Devices::Radios::IRadio>
    {
        int32_t __stdcall SetStateAsync(int32_t value, void** retval) noexcept final try
        {
            clear_abi(retval);
            typename D::abi_guard guard(this->shim());
            *retval = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>>(this->shim().SetStateAsync(*reinterpret_cast<winrt::Windows::Devices::Radios::RadioState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StateChanged(void* handler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Radios::Radio, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Radios::RadioState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Radios::RadioKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Radios::IRadioStatics> : produce_base<D, winrt::Windows::Devices::Radios::IRadioStatics>
    {
        int32_t __stdcall GetRadiosAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Radios::Radio>>>(this->shim().GetRadiosAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Radios
{
    inline auto Radio::GetRadiosAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Radios::Radio>>(*)(IRadioStatics const&), Radio, IRadioStatics>([](IRadioStatics const& f) { return f.GetRadiosAsync(); });
    }
    inline auto Radio::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IRadioStatics const&), Radio, IRadioStatics>([](IRadioStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Radio::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Radio, IRadioStatics>([&](IRadioStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Radio::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>(*)(IRadioStatics const&), Radio, IRadioStatics>([](IRadioStatics const& f) { return f.RequestAccessAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Radios::IRadio> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Radios::IRadioStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Radios::Radio> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
