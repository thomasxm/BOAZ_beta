// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_I2c_H
#define WINRT_Windows_Devices_I2c_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.I2c.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SlaveAddress() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettings)->get_SlaveAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SlaveAddress(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettings)->put_SlaveAddress(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cBusSpeed) consume_Windows_Devices_I2c_II2cConnectionSettings<D>::BusSpeed() const
    {
        winrt::Windows::Devices::I2c::I2cBusSpeed value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettings)->get_BusSpeed(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_II2cConnectionSettings<D>::BusSpeed(winrt::Windows::Devices::I2c::I2cBusSpeed const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettings)->put_BusSpeed(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cSharingMode) consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SharingMode() const
    {
        winrt::Windows::Devices::I2c::I2cSharingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettings)->get_SharingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SharingMode(winrt::Windows::Devices::I2c::I2cSharingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettings)->put_SharingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cConnectionSettings) consume_Windows_Devices_I2c_II2cConnectionSettingsFactory<D>::Create(int32_t slaveAddress) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cConnectionSettingsFactory)->Create(slaveAddress, &value));
        return winrt::Windows::Devices::I2c::I2cConnectionSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cDevice) consume_Windows_Devices_I2c_II2cController<D>::GetDevice(winrt::Windows::Devices::I2c::I2cConnectionSettings const& settings) const
    {
        void* device{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cController)->GetDevice(*(void**)(&settings), &device));
        return winrt::Windows::Devices::I2c::I2cDevice{ device, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::I2c::I2cController>>) consume_Windows_Devices_I2c_II2cControllerStatics<D>::GetControllersAsync(winrt::Windows::Devices::I2c::Provider::II2cProvider const& provider) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cControllerStatics)->GetControllersAsync(*(void**)(&provider), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::I2c::I2cController>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cController>) consume_Windows_Devices_I2c_II2cControllerStatics<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cControllerStatics)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cController>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_I2c_II2cDevice<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cConnectionSettings) consume_Windows_Devices_I2c_II2cDevice<D>::ConnectionSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->get_ConnectionSettings(&value));
        return winrt::Windows::Devices::I2c::I2cConnectionSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_II2cDevice<D>::Write(array_view<uint8_t const> buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->Write(buffer.size(), get_abi(buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cTransferResult) consume_Windows_Devices_I2c_II2cDevice<D>::WritePartial(array_view<uint8_t const> buffer) const
    {
        winrt::Windows::Devices::I2c::I2cTransferResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->WritePartial(buffer.size(), get_abi(buffer), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_II2cDevice<D>::Read(array_view<uint8_t> buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->Read(buffer.size(), put_abi(buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cTransferResult) consume_Windows_Devices_I2c_II2cDevice<D>::ReadPartial(array_view<uint8_t> buffer) const
    {
        winrt::Windows::Devices::I2c::I2cTransferResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->ReadPartial(buffer.size(), put_abi(buffer), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_II2cDevice<D>::WriteRead(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->WriteRead(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), put_abi(readBuffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::I2cTransferResult) consume_Windows_Devices_I2c_II2cDevice<D>::WriteReadPartial(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
    {
        winrt::Windows::Devices::I2c::I2cTransferResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDevice)->WriteReadPartial(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), put_abi(readBuffer), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_I2c_II2cDeviceStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDeviceStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_I2c_II2cDeviceStatics<D>::GetDeviceSelector(param::hstring const& friendlyName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDeviceStatics)->GetDeviceSelectorFromFriendlyName(*(void**)(&friendlyName), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cDevice>) consume_Windows_Devices_I2c_II2cDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId, winrt::Windows::Devices::I2c::I2cConnectionSettings const& settings) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::II2cDeviceStatics)->FromIdAsync(*(void**)(&deviceId), *(void**)(&settings), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cDevice>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::II2cConnectionSettings> : produce_base<D, winrt::Windows::Devices::I2c::II2cConnectionSettings>
    {
        int32_t __stdcall get_SlaveAddress(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SlaveAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SlaveAddress(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SlaveAddress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BusSpeed(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::I2cBusSpeed>(this->shim().BusSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BusSpeed(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BusSpeed(*reinterpret_cast<winrt::Windows::Devices::I2c::I2cBusSpeed const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::I2cSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SharingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SharingMode(*reinterpret_cast<winrt::Windows::Devices::I2c::I2cSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::II2cConnectionSettingsFactory> : produce_base<D, winrt::Windows::Devices::I2c::II2cConnectionSettingsFactory>
    {
        int32_t __stdcall Create(int32_t slaveAddress, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::I2cConnectionSettings>(this->shim().Create(slaveAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::II2cController> : produce_base<D, winrt::Windows::Devices::I2c::II2cController>
    {
        int32_t __stdcall GetDevice(void* settings, void** device) noexcept final try
        {
            clear_abi(device);
            typename D::abi_guard guard(this->shim());
            *device = detach_from<winrt::Windows::Devices::I2c::I2cDevice>(this->shim().GetDevice(*reinterpret_cast<winrt::Windows::Devices::I2c::I2cConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::II2cControllerStatics> : produce_base<D, winrt::Windows::Devices::I2c::II2cControllerStatics>
    {
        int32_t __stdcall GetControllersAsync(void* provider, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::I2c::I2cController>>>(this->shim().GetControllersAsync(*reinterpret_cast<winrt::Windows::Devices::I2c::Provider::II2cProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::II2cDevice> : produce_base<D, winrt::Windows::Devices::I2c::II2cDevice>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::I2cConnectionSettings>(this->shim().ConnectionSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Write(uint32_t __bufferSize, uint8_t* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Write(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WritePartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_I2cTransferResult* result) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::I2c::I2cTransferResult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::I2c::I2cTransferResult>(this->shim().WritePartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Read(uint32_t __bufferSize, uint8_t* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Read(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadPartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_I2cTransferResult* result) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::I2c::I2cTransferResult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::I2c::I2cTransferResult>(this->shim().ReadPartial(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteRead(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteRead(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteReadPartial(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer, struct struct_Windows_Devices_I2c_I2cTransferResult* result) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::I2c::I2cTransferResult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::I2c::I2cTransferResult>(this->shim().WriteReadPartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::II2cDeviceStatics> : produce_base<D, winrt::Windows::Devices::I2c::II2cDeviceStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromFriendlyName(void* friendlyName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&friendlyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void* settings, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Devices::I2c::I2cConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Devices::I2c
{
    inline I2cConnectionSettings::I2cConnectionSettings(int32_t slaveAddress) :
        I2cConnectionSettings(impl::call_factory<I2cConnectionSettings, II2cConnectionSettingsFactory>([&](II2cConnectionSettingsFactory const& f) { return f.Create(slaveAddress); }))
    {
    }
    inline auto I2cController::GetControllersAsync(winrt::Windows::Devices::I2c::Provider::II2cProvider const& provider)
    {
        return impl::call_factory<I2cController, II2cControllerStatics>([&](II2cControllerStatics const& f) { return f.GetControllersAsync(provider); });
    }
    inline auto I2cController::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::I2c::I2cController>(*)(II2cControllerStatics const&), I2cController, II2cControllerStatics>([](II2cControllerStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto I2cDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(II2cDeviceStatics const&), I2cDevice, II2cDeviceStatics>([](II2cDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto I2cDevice::GetDeviceSelector(param::hstring const& friendlyName)
    {
        return impl::call_factory<I2cDevice, II2cDeviceStatics>([&](II2cDeviceStatics const& f) { return f.GetDeviceSelector(friendlyName); });
    }
    inline auto I2cDevice::FromIdAsync(param::hstring const& deviceId, winrt::Windows::Devices::I2c::I2cConnectionSettings const& settings)
    {
        return impl::call_factory<I2cDevice, II2cDeviceStatics>([&](II2cDeviceStatics const& f) { return f.FromIdAsync(deviceId, settings); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::I2c::II2cConnectionSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::II2cConnectionSettingsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::II2cController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::II2cControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::II2cDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::II2cDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::I2cConnectionSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::I2cController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::I2cDevice> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
