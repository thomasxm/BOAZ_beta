// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_H
#define WINRT_Windows_Devices_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Devices.Adc.Provider.2.h"
#include "winrt/impl/Windows.Devices.Gpio.Provider.2.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.2.h"
#include "winrt/impl/Windows.Devices.Pwm.Provider.2.h"
#include "winrt/impl/Windows.Devices.Spi.Provider.2.h"
#include "winrt/impl/Windows.Devices.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider) consume_Windows_Devices_ILowLevelDevicesAggregateProvider<D>::AdcControllerProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider)->get_AdcControllerProvider(&value));
        return winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider) consume_Windows_Devices_ILowLevelDevicesAggregateProvider<D>::PwmControllerProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider)->get_PwmControllerProvider(&value));
        return winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider) consume_Windows_Devices_ILowLevelDevicesAggregateProvider<D>::GpioControllerProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider)->get_GpioControllerProvider(&value));
        return winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::II2cControllerProvider) consume_Windows_Devices_ILowLevelDevicesAggregateProvider<D>::I2cControllerProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider)->get_I2cControllerProvider(&value));
        return winrt::Windows::Devices::I2c::Provider::II2cControllerProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider) consume_Windows_Devices_ILowLevelDevicesAggregateProvider<D>::SpiControllerProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider)->get_SpiControllerProvider(&value));
        return winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::LowLevelDevicesAggregateProvider) consume_Windows_Devices_ILowLevelDevicesAggregateProviderFactory<D>::Create(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider const& adc, winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider const& pwm, winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider const& gpio, winrt::Windows::Devices::I2c::Provider::II2cControllerProvider const& i2c, winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider const& spi) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesAggregateProviderFactory)->Create(*(void**)(&adc), *(void**)(&pwm), *(void**)(&gpio), *(void**)(&i2c), *(void**)(&spi), &value));
        return winrt::Windows::Devices::LowLevelDevicesAggregateProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider) consume_Windows_Devices_ILowLevelDevicesControllerStatics<D>::DefaultProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesControllerStatics)->get_DefaultProvider(&value));
        return winrt::Windows::Devices::ILowLevelDevicesAggregateProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_ILowLevelDevicesControllerStatics<D>::DefaultProvider(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::ILowLevelDevicesControllerStatics)->put_DefaultProvider(*(void**)(&value)));
    }
    template <typename D>
    struct produce<D, winrt::Windows::Devices::ILowLevelDevicesAggregateProvider> : produce_base<D, winrt::Windows::Devices::ILowLevelDevicesAggregateProvider>
    {
        int32_t __stdcall get_AdcControllerProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider>(this->shim().AdcControllerProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PwmControllerProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider>(this->shim().PwmControllerProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GpioControllerProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider>(this->shim().GpioControllerProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_I2cControllerProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider>(this->shim().I2cControllerProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpiControllerProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider>(this->shim().SpiControllerProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::ILowLevelDevicesAggregateProviderFactory> : produce_base<D, winrt::Windows::Devices::ILowLevelDevicesAggregateProviderFactory>
    {
        int32_t __stdcall Create(void* adc, void* pwm, void* gpio, void* i2c, void* spi, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::LowLevelDevicesAggregateProvider>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider const*>(&adc), *reinterpret_cast<winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider const*>(&pwm), *reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider const*>(&gpio), *reinterpret_cast<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider const*>(&i2c), *reinterpret_cast<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider const*>(&spi)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::ILowLevelDevicesController> : produce_base<D, winrt::Windows::Devices::ILowLevelDevicesController>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::ILowLevelDevicesControllerStatics> : produce_base<D, winrt::Windows::Devices::ILowLevelDevicesControllerStatics>
    {
        int32_t __stdcall get_DefaultProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::ILowLevelDevicesAggregateProvider>(this->shim().DefaultProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultProvider(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultProvider(*reinterpret_cast<winrt::Windows::Devices::ILowLevelDevicesAggregateProvider const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices
{
    inline LowLevelDevicesAggregateProvider::LowLevelDevicesAggregateProvider(winrt::Windows::Devices::Adc::Provider::IAdcControllerProvider const& adc, winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider const& pwm, winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider const& gpio, winrt::Windows::Devices::I2c::Provider::II2cControllerProvider const& i2c, winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider const& spi) :
        LowLevelDevicesAggregateProvider(impl::call_factory<LowLevelDevicesAggregateProvider, ILowLevelDevicesAggregateProviderFactory>([&](ILowLevelDevicesAggregateProviderFactory const& f) { return f.Create(adc, pwm, gpio, i2c, spi); }))
    {
    }
    inline auto LowLevelDevicesController::DefaultProvider()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::ILowLevelDevicesAggregateProvider(*)(ILowLevelDevicesControllerStatics const&), LowLevelDevicesController, ILowLevelDevicesControllerStatics>([](ILowLevelDevicesControllerStatics const& f) { return f.DefaultProvider(); });
    }
    inline auto LowLevelDevicesController::DefaultProvider(winrt::Windows::Devices::ILowLevelDevicesAggregateProvider const& value)
    {
        impl::call_factory<LowLevelDevicesController, ILowLevelDevicesControllerStatics>([&](ILowLevelDevicesControllerStatics const& f) { return f.DefaultProvider(value); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::ILowLevelDevicesAggregateProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::ILowLevelDevicesAggregateProviderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::ILowLevelDevicesController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::ILowLevelDevicesControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::LowLevelDevicesAggregateProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::LowLevelDevicesController> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
