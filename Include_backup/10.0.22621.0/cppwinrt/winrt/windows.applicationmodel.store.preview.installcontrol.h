// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_Preview_InstallControl_H
#define WINRT_Windows_ApplicationModel_Store_Preview_InstallControl_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Store.Preview.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Management.Deployment.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.Preview.InstallControl.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::InstallType() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_InstallType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::IsUserInitiated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_IsUserInitiated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::GetCurrentStatus() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->GetCurrentStatus(&result));
        return winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Cancel() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->Cancel());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Restart() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->Restart());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->add_Completed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->remove_Completed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->add_StatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem2<D>::Cancel(param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2)->CancelWithTelemetry(*(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem2<D>::Pause(param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2)->PauseWithTelemetry(*(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem2<D>::Restart(param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2)->RestartWithTelemetry(*(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem3<D>::Children() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3)->get_Children(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem3<D>::ItemOperationsMightAffectOtherItems() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3)->get_ItemOperationsMightAffectOtherItems(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem4<D>::LaunchAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4)->get_LaunchAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem4<D>::LaunchAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4)->put_LaunchAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToDesktopAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_PinToDesktopAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToDesktopAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_PinToDesktopAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToStartAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_PinToStartAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToStartAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_PinToStartAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToTaskbarAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_PinToTaskbarAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToTaskbarAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_PinToTaskbarAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::CompletedInstallToastNotificationMode() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_CompletedInstallToastNotificationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::CompletedInstallToastNotificationMode(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_CompletedInstallToastNotificationMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::InstallInProgressToastNotificationMode() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_InstallInProgressToastNotificationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::InstallInProgressToastNotificationMode(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_InstallInProgressToastNotificationMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AppInstallItems() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->get_AppInstallItems(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::Cancel(param::hstring const& productId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->Cancel(*(void**)(&productId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::Pause(param::hstring const& productId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->Pause(*(void**)(&productId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::Restart(param::hstring const& productId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->Restart(*(void**)(&productId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->add_ItemCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ItemCompleted_revoker>(this, ItemCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->remove_ItemCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->add_ItemStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ItemStatusChanged_revoker>(this, ItemStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->remove_ItemStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AutoUpdateSetting() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->get_AutoUpdateSetting(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AutoUpdateSetting(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->put_AutoUpdateSetting(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AcquisitionIdentity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->get_AcquisitionIdentity(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AcquisitionIdentity(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->put_AcquisitionIdentity(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::GetIsApplicableAsync(param::hstring const& productId, param::hstring const& skuId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->GetIsApplicableAsync(*(void**)(&productId), *(void**)(&skuId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::StartAppInstallAsync(param::hstring const& productId, param::hstring const& skuId, bool repair, bool forceUseOfNonRemovableStorage) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->StartAppInstallAsync(*(void**)(&productId), *(void**)(&skuId), repair, forceUseOfNonRemovableStorage, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::UpdateAppByPackageFamilyNameAsync(param::hstring const& packageFamilyName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->UpdateAppByPackageFamilyNameAsync(*(void**)(&packageFamilyName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::SearchForUpdatesAsync(param::hstring const& productId, param::hstring const& skuId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->SearchForUpdatesAsync(*(void**)(&productId), *(void**)(&skuId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::SearchForAllUpdatesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->SearchForAllUpdatesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::IsStoreBlockedByPolicyAsync(param::hstring const& storeClientName, param::hstring const& storeClientPublisher) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->IsStoreBlockedByPolicyAsync(*(void**)(&storeClientName), *(void**)(&storeClientPublisher), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::GetIsAppAllowedToInstallAsync(param::hstring const& productId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->GetIsAppAllowedToInstallAsync(*(void**)(&productId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::StartAppInstallAsync(param::hstring const& productId, param::hstring const& skuId, bool repair, bool forceUseOfNonRemovableStorage, param::hstring const& catalogId, param::hstring const& bundleId, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->StartAppInstallWithTelemetryAsync(*(void**)(&productId), *(void**)(&skuId), repair, forceUseOfNonRemovableStorage, *(void**)(&catalogId), *(void**)(&bundleId), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::UpdateAppByPackageFamilyNameAsync(param::hstring const& packageFamilyName, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->UpdateAppByPackageFamilyNameWithTelemetryAsync(*(void**)(&packageFamilyName), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::SearchForUpdatesAsync(param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->SearchForUpdatesWithTelemetryAsync(*(void**)(&productId), *(void**)(&skuId), *(void**)(&catalogId), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::SearchForAllUpdatesAsync(param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->SearchForAllUpdatesWithTelemetryAsync(*(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::GetIsAppAllowedToInstallAsync(param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->GetIsAppAllowedToInstallWithTelemetryAsync(*(void**)(&productId), *(void**)(&skuId), *(void**)(&catalogId), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::Cancel(param::hstring const& productId, param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->CancelWithTelemetry(*(void**)(&productId), *(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::Pause(param::hstring const& productId, param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->PauseWithTelemetry(*(void**)(&productId), *(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::Restart(param::hstring const& productId, param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->RestartWithTelemetry(*(void**)(&productId), *(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::StartProductInstallAsync(param::hstring const& productId, param::hstring const& catalogId, param::hstring const& flightId, param::hstring const& clientId, bool repair, bool forceUseOfNonRemovableStorage, param::hstring const& correlationVector, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->StartProductInstallAsync(*(void**)(&productId), *(void**)(&catalogId), *(void**)(&flightId), *(void**)(&clientId), repair, forceUseOfNonRemovableStorage, *(void**)(&correlationVector), *(void**)(&targetVolume), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::StartProductInstallForUserAsync(winrt::Windows::System::User const& user, param::hstring const& productId, param::hstring const& catalogId, param::hstring const& flightId, param::hstring const& clientId, bool repair, bool forceUseOfNonRemovableStorage, param::hstring const& correlationVector, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->StartProductInstallForUserAsync(*(void**)(&user), *(void**)(&productId), *(void**)(&catalogId), *(void**)(&flightId), *(void**)(&clientId), repair, forceUseOfNonRemovableStorage, *(void**)(&correlationVector), *(void**)(&targetVolume), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::UpdateAppByPackageFamilyNameForUserAsync(winrt::Windows::System::User const& user, param::hstring const& packageFamilyName, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->UpdateAppByPackageFamilyNameForUserAsync(*(void**)(&user), *(void**)(&packageFamilyName), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::SearchForUpdatesForUserAsync(winrt::Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->SearchForUpdatesForUserAsync(*(void**)(&user), *(void**)(&productId), *(void**)(&skuId), *(void**)(&catalogId), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::SearchForAllUpdatesForUserAsync(winrt::Windows::System::User const& user, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->SearchForAllUpdatesForUserAsync(*(void**)(&user), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::GetIsAppAllowedToInstallForUserAsync(winrt::Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->GetIsAppAllowedToInstallForUserAsync(*(void**)(&user), *(void**)(&productId), *(void**)(&skuId), *(void**)(&catalogId), *(void**)(&correlationVector), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::GetIsApplicableForUserAsync(winrt::Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->GetIsApplicableForUserAsync(*(void**)(&user), *(void**)(&productId), *(void**)(&skuId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::MoveToFrontOfDownloadQueue(param::hstring const& productId, param::hstring const& correlationVector) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->MoveToFrontOfDownloadQueue(*(void**)(&productId), *(void**)(&correlationVector)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager4<D>::GetFreeUserEntitlementAsync(param::hstring const& storeId, param::hstring const& campaignId, param::hstring const& correlationVector) const
    {
        void* ppAsyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4)->GetFreeUserEntitlementAsync(*(void**)(&storeId), *(void**)(&campaignId), *(void**)(&correlationVector), &ppAsyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>{ ppAsyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager4<D>::GetFreeUserEntitlementForUserAsync(winrt::Windows::System::User const& user, param::hstring const& storeId, param::hstring const& campaignId, param::hstring const& correlationVector) const
    {
        void* ppAsyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4)->GetFreeUserEntitlementForUserAsync(*(void**)(&user), *(void**)(&storeId), *(void**)(&campaignId), *(void**)(&correlationVector), &ppAsyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>{ ppAsyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager4<D>::GetFreeDeviceEntitlementAsync(param::hstring const& storeId, param::hstring const& campaignId, param::hstring const& correlationVector) const
    {
        void* ppAsyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4)->GetFreeDeviceEntitlementAsync(*(void**)(&storeId), *(void**)(&campaignId), *(void**)(&correlationVector), &ppAsyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>{ ppAsyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager5<D>::AppInstallItemsWithGroupSupport() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5)->get_AppInstallItemsWithGroupSupport(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForAllUpdatesAsync(param::hstring const& correlationVector, param::hstring const& clientId, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForAllUpdatesWithUpdateOptionsAsync(*(void**)(&correlationVector), *(void**)(&clientId), *(void**)(&updateOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForAllUpdatesForUserAsync(winrt::Windows::System::User const& user, param::hstring const& correlationVector, param::hstring const& clientId, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForAllUpdatesWithUpdateOptionsForUserAsync(*(void**)(&user), *(void**)(&correlationVector), *(void**)(&clientId), *(void**)(&updateOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForUpdatesAsync(param::hstring const& productId, param::hstring const& skuId, param::hstring const& correlationVector, param::hstring const& clientId, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForUpdatesWithUpdateOptionsAsync(*(void**)(&productId), *(void**)(&skuId), *(void**)(&correlationVector), *(void**)(&clientId), *(void**)(&updateOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForUpdatesForUserAsync(winrt::Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId, param::hstring const& correlationVector, param::hstring const& clientId, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForUpdatesWithUpdateOptionsForUserAsync(*(void**)(&user), *(void**)(&productId), *(void**)(&skuId), *(void**)(&correlationVector), *(void**)(&clientId), *(void**)(&updateOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::StartProductInstallAsync(param::hstring const& productId, param::hstring const& flightId, param::hstring const& clientId, param::hstring const& correlationVector, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const& installOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->StartProductInstallWithOptionsAsync(*(void**)(&productId), *(void**)(&flightId), *(void**)(&clientId), *(void**)(&correlationVector), *(void**)(&installOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::StartProductInstallForUserAsync(winrt::Windows::System::User const& user, param::hstring const& productId, param::hstring const& flightId, param::hstring const& clientId, param::hstring const& correlationVector, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const& installOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->StartProductInstallWithOptionsForUserAsync(*(void**)(&user), *(void**)(&productId), *(void**)(&flightId), *(void**)(&clientId), *(void**)(&correlationVector), *(void**)(&installOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::GetIsPackageIdentityAllowedToInstallAsync(param::hstring const& correlationVector, param::hstring const& packageIdentityName, param::hstring const& publisherCertificateName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->GetIsPackageIdentityAllowedToInstallAsync(*(void**)(&correlationVector), *(void**)(&packageIdentityName), *(void**)(&publisherCertificateName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::GetIsPackageIdentityAllowedToInstallForUserAsync(winrt::Windows::System::User const& user, param::hstring const& correlationVector, param::hstring const& packageIdentityName, param::hstring const& publisherCertificateName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->GetIsPackageIdentityAllowedToInstallForUserAsync(*(void**)(&user), *(void**)(&correlationVector), *(void**)(&packageIdentityName), *(void**)(&publisherCertificateName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager7<D>::CanInstallForAllUsers() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7)->get_CanInstallForAllUsers(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManagerItemEventArgs<D>::Item() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs)->get_Item(&value));
        return winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::CatalogId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_CatalogId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::CatalogId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_CatalogId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::ForceUseOfNonRemovableStorage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_ForceUseOfNonRemovableStorage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::ForceUseOfNonRemovableStorage(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_ForceUseOfNonRemovableStorage(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::AllowForcedAppRestart() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_AllowForcedAppRestart(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::AllowForcedAppRestart(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_AllowForcedAppRestart(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::Repair() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_Repair(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::Repair(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_Repair(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageVolume) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::TargetVolume() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_TargetVolume(&value));
        return winrt::Windows::Management::Deployment::PackageVolume{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::TargetVolume(winrt::Windows::Management::Deployment::PackageVolume const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_TargetVolume(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::LaunchAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_LaunchAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::LaunchAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_LaunchAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToDesktopAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_PinToDesktopAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToDesktopAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_PinToDesktopAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToStartAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_PinToStartAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToStartAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_PinToStartAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToTaskbarAfterInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_PinToTaskbarAfterInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToTaskbarAfterInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_PinToTaskbarAfterInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CompletedInstallToastNotificationMode() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_CompletedInstallToastNotificationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CompletedInstallToastNotificationMode(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_CompletedInstallToastNotificationMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallInProgressToastNotificationMode() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_InstallInProgressToastNotificationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallInProgressToastNotificationMode(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_InstallInProgressToastNotificationMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallForAllUsers() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_InstallForAllUsers(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallForAllUsers(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_InstallForAllUsers(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::StageButDoNotInstall() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_StageButDoNotInstall(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::StageButDoNotInstall(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_StageButDoNotInstall(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CampaignId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_CampaignId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CampaignId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_CampaignId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::ExtendedCampaignId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_ExtendedCampaignId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::ExtendedCampaignId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_ExtendedCampaignId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::InstallState() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_InstallState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::DownloadSizeInBytes() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_DownloadSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::BytesDownloaded() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_BytesDownloaded(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::PercentComplete() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_PercentComplete(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::ErrorCode() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_ErrorCode(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus2<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus2<D>::ReadyForLaunch() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2)->get_ReadyForLaunch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus3<D>::IsStaged() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3)->get_IsStaged(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::CatalogId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->get_CatalogId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::CatalogId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->put_CatalogId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::AllowForcedAppRestart() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->get_AllowForcedAppRestart(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::AllowForcedAppRestart(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->put_AllowForcedAppRestart(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions2<D>::AutomaticallyDownloadAndInstallUpdateIfFound() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2)->get_AutomaticallyDownloadAndInstallUpdateIfFound(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions2<D>::AutomaticallyDownloadAndInstallUpdateIfFound(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2)->put_AutomaticallyDownloadAndInstallUpdateIfFound(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus) consume_Windows_ApplicationModel_Store_Preview_InstallControl_IGetEntitlementResult<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem>
    {
        int32_t __stdcall get_ProductId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstallType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType>(this->shim().InstallType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsUserInitiated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUserInitiated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentStatus(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus>(this->shim().GetCurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Cancel() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Pause() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Restart() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Restart();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Completed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Completed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_StatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2>
    {
        int32_t __stdcall CancelWithTelemetry(void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(*reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseWithTelemetry(void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause(*reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RestartWithTelemetry(void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Restart(*reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3>
    {
        int32_t __stdcall get_Children(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemOperationsMightAffectOtherItems(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ItemOperationsMightAffectOtherItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4>
    {
        int32_t __stdcall get_LaunchAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().LaunchAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LaunchAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LaunchAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5>
    {
        int32_t __stdcall get_PinToDesktopAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PinToDesktopAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PinToDesktopAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToDesktopAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PinToStartAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PinToStartAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PinToStartAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToStartAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PinToTaskbarAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PinToTaskbarAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PinToTaskbarAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToTaskbarAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompletedInstallToastNotificationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().CompletedInstallToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompletedInstallToastNotificationMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompletedInstallToastNotificationMode(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstallInProgressToastNotificationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().InstallInProgressToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InstallInProgressToastNotificationMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InstallInProgressToastNotificationMode(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager>
    {
        int32_t __stdcall get_AppInstallItems(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().AppInstallItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Cancel(void* productId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Pause(void* productId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Restart(void* productId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Restart(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ItemCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ItemCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ItemStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ItemStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_AutoUpdateSetting(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting>(this->shim().AutoUpdateSetting());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoUpdateSetting(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoUpdateSetting(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AcquisitionIdentity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AcquisitionIdentity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AcquisitionIdentity(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcquisitionIdentity(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsApplicableAsync(void* productId, void* skuId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsApplicableAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAppInstallAsync(void* productId, void* skuId, bool repair, bool forceUseOfNonRemovableStorage, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().StartAppInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), repair, forceUseOfNonRemovableStorage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateAppByPackageFamilyNameAsync(void* packageFamilyName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().UpdateAppByPackageFamilyNameAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForUpdatesAsync(void* productId, void* skuId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForAllUpdatesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsStoreBlockedByPolicyAsync(void* storeClientName, void* storeClientPublisher, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsStoreBlockedByPolicyAsync(*reinterpret_cast<hstring const*>(&storeClientName), *reinterpret_cast<hstring const*>(&storeClientPublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsAppAllowedToInstallAsync(void* productId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAppAllowedToInstallAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>
    {
        int32_t __stdcall StartAppInstallWithTelemetryAsync(void* productId, void* skuId, bool repair, bool forceUseOfNonRemovableStorage, void* catalogId, void* bundleId, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().StartAppInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), repair, forceUseOfNonRemovableStorage, *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&bundleId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateAppByPackageFamilyNameWithTelemetryAsync(void* packageFamilyName, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().UpdateAppByPackageFamilyNameAsync(*reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForUpdatesWithTelemetryAsync(void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForAllUpdatesWithTelemetryAsync(void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesAsync(*reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsAppAllowedToInstallWithTelemetryAsync(void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAppAllowedToInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CancelWithTelemetry(void* productId, void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseWithTelemetry(void* productId, void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RestartWithTelemetry(void* productId, void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Restart(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3>
    {
        int32_t __stdcall StartProductInstallAsync(void* productId, void* catalogId, void* flightId, void* clientId, bool repair, bool forceUseOfNonRemovableStorage, void* correlationVector, void* targetVolume, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), repair, forceUseOfNonRemovableStorage, *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<winrt::Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartProductInstallForUserAsync(void* user, void* productId, void* catalogId, void* flightId, void* clientId, bool repair, bool forceUseOfNonRemovableStorage, void* correlationVector, void* targetVolume, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), repair, forceUseOfNonRemovableStorage, *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<winrt::Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateAppByPackageFamilyNameForUserAsync(void* user, void* packageFamilyName, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().UpdateAppByPackageFamilyNameForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForUpdatesForUserAsync(void* user, void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForAllUpdatesForUserAsync(void* user, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsAppAllowedToInstallForUserAsync(void* user, void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAppAllowedToInstallForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsApplicableForUserAsync(void* user, void* productId, void* skuId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsApplicableForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveToFrontOfDownloadQueue(void* productId, void* correlationVector) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MoveToFrontOfDownloadQueue(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4>
    {
        int32_t __stdcall GetFreeUserEntitlementAsync(void* storeId, void* campaignId, void* correlationVector, void** ppAsyncOperation) noexcept final try
        {
            clear_abi(ppAsyncOperation);
            typename D::abi_guard guard(this->shim());
            *ppAsyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>>(this->shim().GetFreeUserEntitlementAsync(*reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<hstring const*>(&campaignId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFreeUserEntitlementForUserAsync(void* user, void* storeId, void* campaignId, void* correlationVector, void** ppAsyncOperation) noexcept final try
        {
            clear_abi(ppAsyncOperation);
            typename D::abi_guard guard(this->shim());
            *ppAsyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>>(this->shim().GetFreeUserEntitlementForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<hstring const*>(&campaignId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFreeDeviceEntitlementAsync(void* storeId, void* campaignId, void* correlationVector, void** ppAsyncOperation) noexcept final try
        {
            clear_abi(ppAsyncOperation);
            typename D::abi_guard guard(this->shim());
            *ppAsyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>>(this->shim().GetFreeDeviceEntitlementAsync(*reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<hstring const*>(&campaignId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5>
    {
        int32_t __stdcall get_AppInstallItemsWithGroupSupport(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().AppInstallItemsWithGroupSupport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>
    {
        int32_t __stdcall SearchForAllUpdatesWithUpdateOptionsAsync(void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesAsync(*reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForAllUpdatesWithUpdateOptionsForUserAsync(void* user, void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForUpdatesWithUpdateOptionsAsync(void* productId, void* skuId, void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SearchForUpdatesWithUpdateOptionsForUserAsync(void* user, void* productId, void* skuId, void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartProductInstallWithOptionsAsync(void* productId, void* flightId, void* clientId, void* correlationVector, void* installOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const*>(&installOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartProductInstallWithOptionsForUserAsync(void* user, void* productId, void* flightId, void* clientId, void* correlationVector, void* installOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const*>(&installOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsPackageIdentityAllowedToInstallAsync(void* correlationVector, void* packageIdentityName, void* publisherCertificateName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsPackageIdentityAllowedToInstallAsync(*reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&packageIdentityName), *reinterpret_cast<hstring const*>(&publisherCertificateName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsPackageIdentityAllowedToInstallForUserAsync(void* user, void* correlationVector, void* packageIdentityName, void* publisherCertificateName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsPackageIdentityAllowedToInstallForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&packageIdentityName), *reinterpret_cast<hstring const*>(&publisherCertificateName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7>
    {
        int32_t __stdcall get_CanInstallForAllUsers(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanInstallForAllUsers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs>
    {
        int32_t __stdcall get_Item(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions>
    {
        int32_t __stdcall get_CatalogId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CatalogId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CatalogId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CatalogId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForceUseOfNonRemovableStorage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ForceUseOfNonRemovableStorage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ForceUseOfNonRemovableStorage(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ForceUseOfNonRemovableStorage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowForcedAppRestart(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowForcedAppRestart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowForcedAppRestart(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowForcedAppRestart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Repair(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Repair());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Repair(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Repair(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetVolume(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Management::Deployment::PackageVolume>(this->shim().TargetVolume());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetVolume(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetVolume(*reinterpret_cast<winrt::Windows::Management::Deployment::PackageVolume const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LaunchAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().LaunchAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LaunchAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LaunchAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2>
    {
        int32_t __stdcall get_PinToDesktopAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PinToDesktopAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PinToDesktopAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToDesktopAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PinToStartAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PinToStartAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PinToStartAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToStartAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PinToTaskbarAfterInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PinToTaskbarAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PinToTaskbarAfterInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToTaskbarAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompletedInstallToastNotificationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().CompletedInstallToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompletedInstallToastNotificationMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompletedInstallToastNotificationMode(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstallInProgressToastNotificationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().InstallInProgressToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InstallInProgressToastNotificationMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InstallInProgressToastNotificationMode(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstallForAllUsers(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().InstallForAllUsers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InstallForAllUsers(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InstallForAllUsers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StageButDoNotInstall(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().StageButDoNotInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StageButDoNotInstall(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StageButDoNotInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CampaignId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CampaignId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CampaignId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CampaignId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedCampaignId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedCampaignId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExtendedCampaignId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExtendedCampaignId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus>
    {
        int32_t __stdcall get_InstallState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState>(this->shim().InstallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DownloadSizeInBytes(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().DownloadSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BytesDownloaded(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().BytesDownloaded());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PercentComplete(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PercentComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadyForLaunch(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ReadyForLaunch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3>
    {
        int32_t __stdcall get_IsStaged(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions>
    {
        int32_t __stdcall get_CatalogId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CatalogId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CatalogId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CatalogId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowForcedAppRestart(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowForcedAppRestart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowForcedAppRestart(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowForcedAppRestart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2>
    {
        int32_t __stdcall get_AutomaticallyDownloadAndInstallUpdateIfFound(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutomaticallyDownloadAndInstallUpdateIfFound());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutomaticallyDownloadAndInstallUpdateIfFound(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutomaticallyDownloadAndInstallUpdateIfFound(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::Preview::InstallControl
{
    inline AppInstallManager::AppInstallManager() :
        AppInstallManager(impl::call_factory_cast<AppInstallManager(*)(winrt::Windows::Foundation::IActivationFactory const&), AppInstallManager>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppInstallManager>(); }))
    {
    }
    inline AppInstallOptions::AppInstallOptions() :
        AppInstallOptions(impl::call_factory_cast<AppInstallOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), AppInstallOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppInstallOptions>(); }))
    {
    }
    inline AppUpdateOptions::AppUpdateOptions() :
        AppUpdateOptions(impl::call_factory_cast<AppUpdateOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), AppUpdateOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppUpdateOptions>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
