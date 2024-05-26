// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Maps_OfflineMaps_H
#define WINRT_Windows_Services_Maps_OfflineMaps_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Services.Maps.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Services.Maps.OfflineMaps.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::Status() const
    {
        winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::EnclosingRegionName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_EnclosingRegionName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::EstimatedSizeInBytes() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_EstimatedSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->add_StatusChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged_revoker consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult>) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::RequestStartDownloadAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->RequestStartDownloadAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageQueryResult<D>::Status() const
    {
        winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage>) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageQueryResult<D>::Packages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult)->get_Packages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStartDownloadResult<D>::Status() const
    {
        winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStatics<D>::FindPackagesAsync(winrt::Windows::Devices::Geolocation::Geopoint const& queryPoint) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics)->FindPackagesAsync(*(void**)(&queryPoint), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStatics<D>::FindPackagesInBoundingBoxAsync(winrt::Windows::Devices::Geolocation::GeoboundingBox const& queryBoundingBox) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics)->FindPackagesInBoundingBoxAsync(*(void**)(&queryBoundingBox), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>) consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStatics<D>::FindPackagesInGeocircleAsync(winrt::Windows::Devices::Geolocation::Geocircle const& queryCircle) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics)->FindPackagesInGeocircleAsync(*(void**)(&queryCircle), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage> : produce_base<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnclosingRegionName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnclosingRegionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EstimatedSizeInBytes(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().EstimatedSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_StatusChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestStartDownloadAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult>>(this->shim().RequestStartDownloadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult> : produce_base<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Packages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage>>(this->shim().Packages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult> : produce_base<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics> : produce_base<D, winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics>
    {
        int32_t __stdcall FindPackagesAsync(void* queryPoint, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>>(this->shim().FindPackagesAsync(*reinterpret_cast<winrt::Windows::Devices::Geolocation::Geopoint const*>(&queryPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindPackagesInBoundingBoxAsync(void* queryBoundingBox, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>>(this->shim().FindPackagesInBoundingBoxAsync(*reinterpret_cast<winrt::Windows::Devices::Geolocation::GeoboundingBox const*>(&queryBoundingBox)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindPackagesInGeocircleAsync(void* queryCircle, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>>(this->shim().FindPackagesInGeocircleAsync(*reinterpret_cast<winrt::Windows::Devices::Geolocation::Geocircle const*>(&queryCircle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Services::Maps::OfflineMaps
{
    inline auto OfflineMapPackage::FindPackagesAsync(winrt::Windows::Devices::Geolocation::Geopoint const& queryPoint)
    {
        return impl::call_factory<OfflineMapPackage, IOfflineMapPackageStatics>([&](IOfflineMapPackageStatics const& f) { return f.FindPackagesAsync(queryPoint); });
    }
    inline auto OfflineMapPackage::FindPackagesInBoundingBoxAsync(winrt::Windows::Devices::Geolocation::GeoboundingBox const& queryBoundingBox)
    {
        return impl::call_factory<OfflineMapPackage, IOfflineMapPackageStatics>([&](IOfflineMapPackageStatics const& f) { return f.FindPackagesInBoundingBoxAsync(queryBoundingBox); });
    }
    inline auto OfflineMapPackage::FindPackagesInGeocircleAsync(winrt::Windows::Devices::Geolocation::Geocircle const& queryCircle)
    {
        return impl::call_factory<OfflineMapPackage, IOfflineMapPackageStatics>([&](IOfflineMapPackageStatics const& f) { return f.FindPackagesInGeocircleAsync(queryCircle); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
