// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_AppExtensions_H
#define WINRT_Windows_ApplicationModel_AppExtensions_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.ApplicationModel.AppExtensions.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppInfo) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::AppInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->get_AppInfo(&value));
        return winrt::Windows::ApplicationModel::AppInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IPropertySet>) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::GetExtensionPropertiesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->GetExtensionPropertiesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IPropertySet>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::GetPublicFolderAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension)->GetPublicFolderAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtension2<D>::AppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtension2)->get_AppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>>) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::FindAllAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->FindAllAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::RequestRemovePackageAsync(param::hstring const& packageFullName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->RequestRemovePackageAsync(*(void**)(&packageFullName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageInstalled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PackageInstalled_revoker>(this, PackageInstalled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageInstalled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageUpdating(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PackageUpdating_revoker>(this, PackageUpdating(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageUpdating(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PackageUpdated_revoker>(this, PackageUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageUninstalling(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PackageUninstalling_revoker>(this, PackageUninstalling(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageUninstalling(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PackageStatusChanged_revoker>(this, PackageStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalogStatics<D>::Open(param::hstring const& appExtensionName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics)->Open(*(void**)(&appExtensionName), &value));
        return winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageInstalledEventArgs<D>::AppExtensionName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs)->get_AppExtensionName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageInstalledEventArgs<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageInstalledEventArgs<D>::Extensions() const
    {
        void* values{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs)->get_Extensions(&values));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>{ values, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageStatusChangedEventArgs<D>::AppExtensionName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs)->get_AppExtensionName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageStatusChangedEventArgs<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUninstallingEventArgs<D>::AppExtensionName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs)->get_AppExtensionName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUninstallingEventArgs<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatedEventArgs<D>::AppExtensionName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs)->get_AppExtensionName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatedEventArgs<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatedEventArgs<D>::Extensions() const
    {
        void* values{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs)->get_Extensions(&values));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>{ values, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatingEventArgs<D>::AppExtensionName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs)->get_AppExtensionName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatingEventArgs<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtension> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtension>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
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
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppInfo>(this->shim().AppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetExtensionPropertiesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IPropertySet>>(this->shim().GetExtensionPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPublicFolderAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetPublicFolderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtension2> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtension2>
    {
        int32_t __stdcall get_AppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog>
    {
        int32_t __stdcall FindAllAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestRemovePackageAsync(void* packageFullName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestRemovePackageAsync(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PackageInstalled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PackageInstalled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PackageInstalled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageInstalled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PackageUpdating(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PackageUpdating(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PackageUpdating(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageUpdating(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PackageUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PackageUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PackageUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PackageUninstalling(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PackageUninstalling(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PackageUninstalling(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageUninstalling(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PackageStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PackageStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PackageStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics>
    {
        int32_t __stdcall Open(void* appExtensionName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog>(this->shim().Open(*reinterpret_cast<hstring const*>(&appExtensionName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs>
    {
        int32_t __stdcall get_AppExtensionName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Extensions(void** values) noexcept final try
        {
            clear_abi(values);
            typename D::abi_guard guard(this->shim());
            *values = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>>(this->shim().Extensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs>
    {
        int32_t __stdcall get_AppExtensionName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs>
    {
        int32_t __stdcall get_AppExtensionName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs>
    {
        int32_t __stdcall get_AppExtensionName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Extensions(void** values) noexcept final try
        {
            clear_abi(values);
            typename D::abi_guard guard(this->shim());
            *values = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppExtensions::AppExtension>>(this->shim().Extensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs>
    {
        int32_t __stdcall get_AppExtensionName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppExtensions
{
    inline auto AppExtensionCatalog::Open(param::hstring const& appExtensionName)
    {
        return impl::call_factory<AppExtensionCatalog, IAppExtensionCatalogStatics>([&](IAppExtensionCatalogStatics const& f) { return f.Open(appExtensionName); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtension2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
