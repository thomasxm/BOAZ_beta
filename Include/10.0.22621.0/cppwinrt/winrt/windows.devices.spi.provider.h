// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Spi_Provider_H
#define WINRT_Windows_Devices_Spi_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Spi.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Spi.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ChipSelectLine() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_ChipSelectLine(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ChipSelectLine(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_ChipSelectLine(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Spi::Provider::ProviderSpiMode) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::Mode() const
    {
        winrt::Windows::Devices::Spi::Provider::ProviderSpiMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::Mode(winrt::Windows::Devices::Spi::Provider::ProviderSpiMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::DataBitLength() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_DataBitLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::DataBitLength(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_DataBitLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ClockFrequency() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_ClockFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ClockFrequency(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_ClockFrequency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Spi::Provider::ProviderSpiSharingMode) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::SharingMode() const
    {
        winrt::Windows::Devices::Spi::Provider::ProviderSpiSharingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_SharingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::SharingMode(winrt::Windows::Devices::Spi::Provider::ProviderSpiSharingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_SharingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings) consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettingsFactory<D>::Create(int32_t chipSelectLine) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory)->Create(chipSelectLine, &value));
        return winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider) consume_Windows_Devices_Spi_Provider_ISpiControllerProvider<D>::GetDeviceProvider(winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings const& settings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider)->GetDeviceProvider(*(void**)(&settings), &result));
        return winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings) consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::ConnectionSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider)->get_ConnectionSettings(&value));
        return winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::Write(array_view<uint8_t const> buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider)->Write(buffer.size(), get_abi(buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::Read(array_view<uint8_t> buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider)->Read(buffer.size(), put_abi(buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::TransferSequential(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider)->TransferSequential(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), put_abi(readBuffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::TransferFullDuplex(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider)->TransferFullDuplex(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), put_abi(readBuffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider>>) consume_Windows_Devices_Spi_Provider_ISpiProvider<D>::GetControllersAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Spi::Provider::ISpiProvider)->GetControllersAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider>>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings> : produce_base<D, winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings>
    {
        int32_t __stdcall get_ChipSelectLine(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ChipSelectLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChipSelectLine(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChipSelectLine(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Spi::Provider::ProviderSpiMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::Devices::Spi::Provider::ProviderSpiMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataBitLength(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DataBitLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataBitLength(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataBitLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClockFrequency(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ClockFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClockFrequency(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClockFrequency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Spi::Provider::ProviderSpiSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SharingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SharingMode(*reinterpret_cast<winrt::Windows::Devices::Spi::Provider::ProviderSpiSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory> : produce_base<D, winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>
    {
        int32_t __stdcall Create(int32_t chipSelectLine, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>(this->shim().Create(chipSelectLine));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider> : produce_base<D, winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider>
    {
        int32_t __stdcall GetDeviceProvider(void* settings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider>(this->shim().GetDeviceProvider(*reinterpret_cast<winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider> : produce_base<D, winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider>
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
            *value = detach_from<winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>(this->shim().ConnectionSettings());
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
        int32_t __stdcall Read(uint32_t __bufferSize, uint8_t* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Read(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferSequential(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferSequential(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferFullDuplex(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferFullDuplex(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Spi::Provider::ISpiProvider> : produce_base<D, winrt::Windows::Devices::Spi::Provider::ISpiProvider>
    {
        int32_t __stdcall GetControllersAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider>>>(this->shim().GetControllersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Devices::Spi::Provider
{
    inline ProviderSpiConnectionSettings::ProviderSpiConnectionSettings(int32_t chipSelectLine) :
        ProviderSpiConnectionSettings(impl::call_factory<ProviderSpiConnectionSettings, IProviderSpiConnectionSettingsFactory>([&](IProviderSpiConnectionSettingsFactory const& f) { return f.Create(chipSelectLine); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Spi::Provider::ISpiProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
