// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Adc_H
#define WINRT_Windows_Devices_Adc_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.Adc.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Adc.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Adc::AdcController) consume_Windows_Devices_Adc_IAdcChannel<D>::Controller() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcChannel)->get_Controller(&value));
        return winrt::Windows::Devices::Adc::AdcController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_IAdcChannel<D>::ReadValue() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcChannel)->ReadValue(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Adc_IAdcChannel<D>::ReadRatio() const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcChannel)->ReadRatio(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_IAdcController<D>::ChannelCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->get_ChannelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_IAdcController<D>::ResolutionInBits() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->get_ResolutionInBits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_IAdcController<D>::MinValue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->get_MinValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Adc_IAdcController<D>::MaxValue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->get_MaxValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Adc::AdcChannelMode) consume_Windows_Devices_Adc_IAdcController<D>::ChannelMode() const
    {
        winrt::Windows::Devices::Adc::AdcChannelMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->get_ChannelMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Adc_IAdcController<D>::ChannelMode(winrt::Windows::Devices::Adc::AdcChannelMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->put_ChannelMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Adc_IAdcController<D>::IsChannelModeSupported(winrt::Windows::Devices::Adc::AdcChannelMode const& channelMode) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->IsChannelModeSupported(static_cast<int32_t>(channelMode), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Adc::AdcChannel) consume_Windows_Devices_Adc_IAdcController<D>::OpenChannel(int32_t channelNumber) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcController)->OpenChannel(channelNumber, &result));
        return winrt::Windows::Devices::Adc::AdcChannel{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Adc::AdcController>>) consume_Windows_Devices_Adc_IAdcControllerStatics<D>::GetControllersAsync(winrt::Windows::Devices::Adc::Provider::IAdcProvider const& provider) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcControllerStatics)->GetControllersAsync(*(void**)(&provider), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Adc::AdcController>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Adc::AdcController>) consume_Windows_Devices_Adc_IAdcControllerStatics2<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Adc::IAdcControllerStatics2)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Adc::AdcController>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Adc::IAdcChannel> : produce_base<D, winrt::Windows::Devices::Adc::IAdcChannel>
    {
        int32_t __stdcall get_Controller(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Adc::AdcController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadValue(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().ReadValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadRatio(double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().ReadRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Adc::IAdcController> : produce_base<D, winrt::Windows::Devices::Adc::IAdcController>
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
            *value = detach_from<winrt::Windows::Devices::Adc::AdcChannelMode>(this->shim().ChannelMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChannelMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChannelMode(*reinterpret_cast<winrt::Windows::Devices::Adc::AdcChannelMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsChannelModeSupported(int32_t channelMode, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsChannelModeSupported(*reinterpret_cast<winrt::Windows::Devices::Adc::AdcChannelMode const*>(&channelMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenChannel(int32_t channelNumber, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Adc::AdcChannel>(this->shim().OpenChannel(channelNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Adc::IAdcControllerStatics> : produce_base<D, winrt::Windows::Devices::Adc::IAdcControllerStatics>
    {
        int32_t __stdcall GetControllersAsync(void* provider, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Adc::AdcController>>>(this->shim().GetControllersAsync(*reinterpret_cast<winrt::Windows::Devices::Adc::Provider::IAdcProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Adc::IAdcControllerStatics2> : produce_base<D, winrt::Windows::Devices::Adc::IAdcControllerStatics2>
    {
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Adc::AdcController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Adc
{
    inline auto AdcController::GetControllersAsync(winrt::Windows::Devices::Adc::Provider::IAdcProvider const& provider)
    {
        return impl::call_factory<AdcController, IAdcControllerStatics>([&](IAdcControllerStatics const& f) { return f.GetControllersAsync(provider); });
    }
    inline auto AdcController::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Adc::AdcController>(*)(IAdcControllerStatics2 const&), AdcController, IAdcControllerStatics2>([](IAdcControllerStatics2 const& f) { return f.GetDefaultAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Adc::IAdcChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Adc::IAdcController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Adc::IAdcControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Adc::IAdcControllerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Adc::AdcChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Adc::AdcController> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
