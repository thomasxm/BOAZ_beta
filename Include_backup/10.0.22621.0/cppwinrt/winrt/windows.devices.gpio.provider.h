// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Gpio_Provider_H
#define WINRT_Windows_Devices_Gpio_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Gpio.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Gpio.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Gpio_Provider_IGpioControllerProvider<D>::PinCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider)->get_PinCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider) consume_Windows_Devices_Gpio_Provider_IGpioControllerProvider<D>::OpenPinProvider(int32_t pin, winrt::Windows::Devices::Gpio::Provider::ProviderGpioSharingMode const& sharingMode) const
    {
        void* gpioPinProvider{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider)->OpenPinProvider(pin, static_cast<int32_t>(sharingMode), &gpioPinProvider));
        return winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider{ gpioPinProvider, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::ValueChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider, winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->add_ValueChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::ValueChanged_revoker consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::ValueChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider, winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ValueChanged_revoker>(this, ValueChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::ValueChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->remove_ValueChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::DebounceTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->get_DebounceTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::DebounceTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->put_DebounceTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::PinNumber() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->get_PinNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::ProviderGpioSharingMode) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::SharingMode() const
    {
        winrt::Windows::Devices::Gpio::Provider::ProviderGpioSharingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->get_SharingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::IsDriveModeSupported(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode const& driveMode) const
    {
        bool supported{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->IsDriveModeSupported(static_cast<int32_t>(driveMode), &supported));
        return supported;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::GetDriveMode() const
    {
        winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->GetDriveMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::SetDriveMode(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->SetDriveMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::Write(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinValue const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->Write(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinValue) consume_Windows_Devices_Gpio_Provider_IGpioPinProvider<D>::Read() const
    {
        winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinValue value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider)->Read(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinEdge) consume_Windows_Devices_Gpio_Provider_IGpioPinProviderValueChangedEventArgs<D>::Edge() const
    {
        winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinEdge value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgs)->get_Edge(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs) consume_Windows_Devices_Gpio_Provider_IGpioPinProviderValueChangedEventArgsFactory<D>::Create(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinEdge const& edge) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgsFactory)->Create(static_cast<int32_t>(edge), &value));
        return winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider>) consume_Windows_Devices_Gpio_Provider_IGpioProvider<D>::GetControllers() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::Provider::IGpioProvider)->GetControllers(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider>{ result, take_ownership_from_abi };
    }
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider> : produce_base<D, winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider>
    {
        int32_t __stdcall get_PinCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PinCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenPinProvider(int32_t pin, int32_t sharingMode, void** gpioPinProvider) noexcept final try
        {
            clear_abi(gpioPinProvider);
            typename D::abi_guard guard(this->shim());
            *gpioPinProvider = detach_from<winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider>(this->shim().OpenPinProvider(pin, *reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::ProviderGpioSharingMode const*>(&sharingMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider> : produce_base<D, winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider>
    {
        int32_t __stdcall add_ValueChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ValueChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider, winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ValueChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ValueChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_DebounceTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DebounceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DebounceTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DebounceTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PinNumber(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PinNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::Provider::ProviderGpioSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsDriveModeSupported(int32_t driveMode, bool* supported) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *supported = detach_from<bool>(this->shim().IsDriveModeSupported(*reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode const*>(&driveMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDriveMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode>(this->shim().GetDriveMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDriveMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDriveMode(*reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinDriveMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Write(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Write(*reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Read(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinValue>(this->shim().Read());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgs>
    {
        int32_t __stdcall get_Edge(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinEdge>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgsFactory> : produce_base<D, winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgsFactory>
    {
        int32_t __stdcall Create(int32_t edge, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinEdge const*>(&edge)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::Provider::IGpioProvider> : produce_base<D, winrt::Windows::Devices::Gpio::Provider::IGpioProvider>
    {
        int32_t __stdcall GetControllers(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider>>(this->shim().GetControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Devices::Gpio::Provider
{
    inline GpioPinProviderValueChangedEventArgs::GpioPinProviderValueChangedEventArgs(winrt::Windows::Devices::Gpio::Provider::ProviderGpioPinEdge const& edge) :
        GpioPinProviderValueChangedEventArgs(impl::call_factory<GpioPinProviderValueChangedEventArgs, IGpioPinProviderValueChangedEventArgsFactory>([&](IGpioPinProviderValueChangedEventArgsFactory const& f) { return f.Create(edge); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Gpio::Provider::IGpioControllerProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::Provider::IGpioPinProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::Provider::IGpioPinProviderValueChangedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::Provider::IGpioProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::Provider::GpioPinProviderValueChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
