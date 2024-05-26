// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Geolocation_Provider_H
#define WINRT_Windows_Devices_Geolocation_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Geolocation.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Geolocation.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::IsOverridden() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider)->get_IsOverridden(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Provider::LocationOverrideStatus) consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::SetOverridePosition(winrt::Windows::Devices::Geolocation::BasicGeoposition const& newPosition, winrt::Windows::Devices::Geolocation::PositionSource const& positionSource, double accuracyInMeters) const
    {
        winrt::Windows::Devices::Geolocation::Provider::LocationOverrideStatus result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider)->SetOverridePosition(impl::bind_in(newPosition), static_cast<int32_t>(positionSource), accuracyInMeters, reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::ClearOverridePosition() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider)->ClearOverridePosition());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::IsOverriddenChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider)->add_IsOverriddenChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::IsOverriddenChanged_revoker consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::IsOverriddenChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsOverriddenChanged_revoker>(this, IsOverriddenChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>::IsOverriddenChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider)->remove_IsOverriddenChanged(impl::bind_in(token));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider> : produce_base<D, winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider>
    {
        int32_t __stdcall get_IsOverridden(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverridden());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetOverridePosition(struct struct_Windows_Devices_Geolocation_BasicGeoposition newPosition, int32_t positionSource, double accuracyInMeters, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Geolocation::Provider::LocationOverrideStatus>(this->shim().SetOverridePosition(*reinterpret_cast<winrt::Windows::Devices::Geolocation::BasicGeoposition const*>(&newPosition), *reinterpret_cast<winrt::Windows::Devices::Geolocation::PositionSource const*>(&positionSource), accuracyInMeters));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearOverridePosition() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearOverridePosition();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_IsOverriddenChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsOverriddenChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsOverriddenChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOverriddenChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation::Provider
{
    inline GeolocationProvider::GeolocationProvider() :
        GeolocationProvider(impl::call_factory_cast<GeolocationProvider(*)(winrt::Windows::Foundation::IActivationFactory const&), GeolocationProvider>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<GeolocationProvider>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Geolocation::Provider::GeolocationProvider> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
