// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Profile_SystemManufacturers_H
#define WINRT_Windows_System_Profile_SystemManufacturers_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.Profile.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Profile.SystemManufacturers.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_System_Profile_SystemManufacturers_IOemSupportInfo<D>::SupportLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo)->get_SupportLink(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_System_Profile_SystemManufacturers_IOemSupportInfo<D>::SupportAppLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo)->get_SupportAppLink(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_IOemSupportInfo<D>::SupportProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo)->get_SupportProvider(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISmbiosInformationStatics<D>::SerialNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics)->get_SerialNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::OperatingSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_OperatingSystem(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::FriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_FriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemManufacturer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemManufacturer(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemProductName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemProductName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemSku() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemSku(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemHardwareVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemHardwareVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemFirmwareVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemFirmwareVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportInfoStatics<D>::LocalSystemEdition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics)->get_LocalSystemEdition(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportInfoStatics<D>::OemSupportInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics)->get_OemSupportInfo(&value));
        return winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo) consume_Windows_System_Profile_SystemManufacturers_ISystemSupportInfoStatics2<D>::LocalDeviceInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2)->get_LocalDeviceInfo(&value));
        return winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo> : produce_base<D, winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo>
    {
        int32_t __stdcall get_SupportLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().SupportLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportAppLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().SupportAppLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SupportProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics> : produce_base<D, winrt::Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics>
    {
        int32_t __stdcall get_SerialNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SerialNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo> : produce_base<D, winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo>
    {
        int32_t __stdcall get_OperatingSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OperatingSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemManufacturer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemManufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemProductName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemProductName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemSku(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemSku());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemHardwareVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemHardwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemFirmwareVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemFirmwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics> : produce_base<D, winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics>
    {
        int32_t __stdcall get_LocalSystemEdition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalSystemEdition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OemSupportInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo>(this->shim().OemSupportInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2> : produce_base<D, winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2>
    {
        int32_t __stdcall get_LocalDeviceInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo>(this->shim().LocalDeviceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Profile::SystemManufacturers
{
    inline auto SmbiosInformation::SerialNumber()
    {
        return impl::call_factory_cast<hstring(*)(ISmbiosInformationStatics const&), SmbiosInformation, ISmbiosInformationStatics>([](ISmbiosInformationStatics const& f) { return f.SerialNumber(); });
    }
    inline auto SystemSupportInfo::LocalSystemEdition()
    {
        return impl::call_factory_cast<hstring(*)(ISystemSupportInfoStatics const&), SystemSupportInfo, ISystemSupportInfoStatics>([](ISystemSupportInfoStatics const& f) { return f.LocalSystemEdition(); });
    }
    inline auto SystemSupportInfo::OemSupportInfo()
    {
        return impl::call_factory_cast<winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo(*)(ISystemSupportInfoStatics const&), SystemSupportInfo, ISystemSupportInfoStatics>([](ISystemSupportInfoStatics const& f) { return f.OemSupportInfo(); });
    }
    inline auto SystemSupportInfo::LocalDeviceInfo()
    {
        return impl::call_factory_cast<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo(*)(ISystemSupportInfoStatics2 const&), SystemSupportInfo, ISystemSupportInfoStatics2>([](ISystemSupportInfoStatics2 const& f) { return f.LocalDeviceInfo(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::SmbiosInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportInfo> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
