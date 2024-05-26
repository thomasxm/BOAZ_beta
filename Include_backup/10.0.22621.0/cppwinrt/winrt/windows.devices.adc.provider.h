// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Adc_Provider_H
#define WINRT_Windows_Devices_Adc_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Adc.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Adc.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::ChannelCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->get_ChannelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::ResolutionInBits() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->get_ResolutionInBits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::MinValue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->get_MinValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::MaxValue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->get_MaxValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::ChannelMode() const
    {
        winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->get_ChannelMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::ChannelMode(winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->put_ChannelMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::IsChannelModeSupported(winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode const& channelMode) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->IsChannelModeSupported(static_cast<int32_t>(channelMode), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::AcquireChannel(int32_t channel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->AcquireChannel(channel));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::ReleaseChannel(int32_t channel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->ReleaseChannel(channel));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_Provider_IAdcControllerProvider<D>::ReadValue(int32_t channelNumber) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider)->ReadValue(channelNumber, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider>) consume_Windows_Devices_Adc_Provider_IAdcProvider<D>::GetControllers() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::Provider::IAdcProvider)->GetControllers(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider>{ result, take_ownership_from_abi };
    }
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider> : produce_base<D, winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider>
    {
        int32_t __stdcall get_ChannelCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ChannelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResolutionInBits(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ResolutionInBits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinValue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MinValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxValue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChannelMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode>(this->shim().ChannelMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChannelMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChannelMode(*reinterpret_cast<winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsChannelModeSupported(int32_t channelMode, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsChannelModeSupported(*reinterpret_cast<winrt::Windows::Devices::Adc::Provider::ProviderAdcChannelMode const*>(&channelMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcquireChannel(int32_t channel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcquireChannel(channel);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleaseChannel(int32_t channel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseChannel(channel);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadValue(int32_t channelNumber, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().ReadValue(channelNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Adc::Provider::IAdcProvider> : produce_base<D, winrt::Windows::Devices::Adc::Provider::IAdcProvider>
    {
        int32_t __stdcall GetControllers(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider>>(this->shim().GetControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Devices::Adc::Provider
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Adc::Provider::IAdcProvider> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
