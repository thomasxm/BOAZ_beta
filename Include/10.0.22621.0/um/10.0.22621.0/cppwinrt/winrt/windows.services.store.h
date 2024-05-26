// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Store_H
#define WINRT_Windows_Services_Store_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Services.Store.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePackageLicense) consume_Windows_Services_Store_IStoreAcquireLicenseResult<D>::StorePackageLicense() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAcquireLicenseResult)->get_StorePackageLicense(&value));
        return winrt::Windows::Services::Store::StorePackageLicense{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreAcquireLicenseResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAcquireLicenseResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreAppLicense<D>::SkuStoreId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_SkuStoreId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreAppLicense<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreAppLicense<D>::IsTrial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_IsTrial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStoreAppLicense<D>::ExpirationDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_ExpirationDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreAppLicense<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreLicense>) consume_Windows_Services_Store_IStoreAppLicense<D>::AddOnLicenses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_AddOnLicenses(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreLicense>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Services_Store_IStoreAppLicense<D>::TrialTimeRemaining() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_TrialTimeRemaining(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreAppLicense<D>::IsTrialOwnedByThisUser() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_IsTrialOwnedByThisUser(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreAppLicense<D>::TrialUniqueId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense)->get_TrialUniqueId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreAppLicense2<D>::IsDiscLicense() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAppLicense2)->get_IsDiscLicense(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreAvailability<D>::StoreId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAvailability)->get_StoreId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStoreAvailability<D>::EndDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAvailability)->get_EndDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePrice) consume_Windows_Services_Store_IStoreAvailability<D>::Price() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAvailability)->get_Price(&value));
        return winrt::Windows::Services::Store::StorePrice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreAvailability<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAvailability)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreAvailability<D>::RequestPurchaseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAvailability)->RequestPurchaseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreAvailability<D>::RequestPurchaseAsync(winrt::Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreAvailability)->RequestPurchaseWithPurchasePropertiesAsync(*(void**)(&storePurchaseProperties), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>::LicensableSku() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult)->get_LicensableSku(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreCanLicenseStatus) consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>::Status() const
    {
        winrt::Windows::Services::Store::StoreCanLicenseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreCollectionData<D>::IsTrial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_IsTrial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreCollectionData<D>::CampaignId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_CampaignId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreCollectionData<D>::DeveloperOfferId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_DeveloperOfferId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStoreCollectionData<D>::AcquiredDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_AcquiredDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStoreCollectionData<D>::StartDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_StartDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStoreCollectionData<D>::EndDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_EndDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Services_Store_IStoreCollectionData<D>::TrialTimeRemaining() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_TrialTimeRemaining(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreCollectionData<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreCollectionData)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreConsumableStatus) consume_Windows_Services_Store_IStoreConsumableResult<D>::Status() const
    {
        winrt::Windows::Services::Store::StoreConsumableStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreConsumableResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Services_Store_IStoreConsumableResult<D>::TrackingId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreConsumableResult)->get_TrackingId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreConsumableResult<D>::BalanceRemaining() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreConsumableResult)->get_BalanceRemaining(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreConsumableResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreConsumableResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Services_Store_IStoreContext<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreContext, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->add_OfflineLicensesChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged_revoker consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreContext, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, OfflineLicensesChanged_revoker>(this, OfflineLicensesChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->remove_OfflineLicensesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Services_Store_IStoreContext<D>::GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetCustomerPurchaseIdAsync(*(void**)(&serviceTicket), *(void**)(&publisherUserId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Services_Store_IStoreContext<D>::GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetCustomerCollectionsIdAsync(*(void**)(&serviceTicket), *(void**)(&publisherUserId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreAppLicense>) consume_Windows_Services_Store_IStoreContext<D>::GetAppLicenseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetAppLicenseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreAppLicense>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductResult>) consume_Windows_Services_Store_IStoreContext<D>::GetStoreProductForCurrentAppAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetStoreProductForCurrentAppAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>) consume_Windows_Services_Store_IStoreContext<D>::GetStoreProductsAsync(param::async_iterable<hstring> const& productKinds, param::async_iterable<hstring> const& storeIds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetStoreProductsAsync(*(void**)(&productKinds), *(void**)(&storeIds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>) consume_Windows_Services_Store_IStoreContext<D>::GetAssociatedStoreProductsAsync(param::async_iterable<hstring> const& productKinds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetAssociatedStoreProductsAsync(*(void**)(&productKinds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>) consume_Windows_Services_Store_IStoreContext<D>::GetAssociatedStoreProductsWithPagingAsync(param::async_iterable<hstring> const& productKinds, uint32_t maxItemsToRetrievePerPage) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetAssociatedStoreProductsWithPagingAsync(*(void**)(&productKinds), maxItemsToRetrievePerPage, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>) consume_Windows_Services_Store_IStoreContext<D>::GetUserCollectionAsync(param::async_iterable<hstring> const& productKinds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetUserCollectionAsync(*(void**)(&productKinds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>) consume_Windows_Services_Store_IStoreContext<D>::GetUserCollectionWithPagingAsync(param::async_iterable<hstring> const& productKinds, uint32_t maxItemsToRetrievePerPage) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetUserCollectionWithPagingAsync(*(void**)(&productKinds), maxItemsToRetrievePerPage, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreConsumableResult>) consume_Windows_Services_Store_IStoreContext<D>::ReportConsumableFulfillmentAsync(param::hstring const& productStoreId, uint32_t quantity, winrt::guid const& trackingId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->ReportConsumableFulfillmentAsync(*(void**)(&productStoreId), quantity, impl::bind_in(trackingId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreConsumableResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreConsumableResult>) consume_Windows_Services_Store_IStoreContext<D>::GetConsumableBalanceRemainingAsync(param::hstring const& productStoreId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetConsumableBalanceRemainingAsync(*(void**)(&productStoreId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreConsumableResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreAcquireLicenseResult>) consume_Windows_Services_Store_IStoreContext<D>::AcquireStoreLicenseForOptionalPackageAsync(winrt::Windows::ApplicationModel::Package const& optionalPackage) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->AcquireStoreLicenseForOptionalPackageAsync(*(void**)(&optionalPackage), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreAcquireLicenseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreContext<D>::RequestPurchaseAsync(param::hstring const& storeId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->RequestPurchaseAsync(*(void**)(&storeId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreContext<D>::RequestPurchaseAsync(param::hstring const& storeId, winrt::Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->RequestPurchaseWithPurchasePropertiesAsync(*(void**)(&storeId), *(void**)(&storePurchaseProperties), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StorePackageUpdate>>) consume_Windows_Services_Store_IStoreContext<D>::GetAppAndOptionalStorePackageUpdatesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->GetAppAndOptionalStorePackageUpdatesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StorePackageUpdate>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext<D>::RequestDownloadStorePackageUpdatesAsync(param::async_iterable<winrt::Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->RequestDownloadStorePackageUpdatesAsync(*(void**)(&storePackageUpdates), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext<D>::RequestDownloadAndInstallStorePackageUpdatesAsync(param::async_iterable<winrt::Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->RequestDownloadAndInstallStorePackageUpdatesAsync(*(void**)(&storePackageUpdates), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext<D>::RequestDownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext)->RequestDownloadAndInstallStorePackagesAsync(*(void**)(&storeIds), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductResult>) consume_Windows_Services_Store_IStoreContext2<D>::FindStoreProductForPackageAsync(param::async_iterable<hstring> const& productKinds, winrt::Windows::ApplicationModel::Package const& package) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext2)->FindStoreProductForPackageAsync(*(void**)(&productKinds), *(void**)(&package), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreContext3<D>::CanSilentlyDownloadStorePackageUpdates() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->get_CanSilentlyDownloadStorePackageUpdates(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext3<D>::TrySilentDownloadStorePackageUpdatesAsync(param::async_iterable<winrt::Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->TrySilentDownloadStorePackageUpdatesAsync(*(void**)(&storePackageUpdates), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext3<D>::TrySilentDownloadAndInstallStorePackageUpdatesAsync(param::async_iterable<winrt::Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->TrySilentDownloadAndInstallStorePackageUpdatesAsync(*(void**)(&storePackageUpdates), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult>) consume_Windows_Services_Store_IStoreContext3<D>::CanAcquireStoreLicenseForOptionalPackageAsync(winrt::Windows::ApplicationModel::Package const& optionalPackage) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->CanAcquireStoreLicenseForOptionalPackageAsync(*(void**)(&optionalPackage), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult>) consume_Windows_Services_Store_IStoreContext3<D>::CanAcquireStoreLicenseAsync(param::hstring const& productStoreId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->CanAcquireStoreLicenseAsync(*(void**)(&productStoreId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>) consume_Windows_Services_Store_IStoreContext3<D>::GetStoreProductsAsync(param::async_iterable<hstring> const& productKinds, param::async_iterable<hstring> const& storeIds, winrt::Windows::Services::Store::StoreProductOptions const& storeProductOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->GetStoreProductsWithOptionsAsync(*(void**)(&productKinds), *(void**)(&storeIds), *(void**)(&storeProductOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>) consume_Windows_Services_Store_IStoreContext3<D>::GetAssociatedStoreQueueItemsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->GetAssociatedStoreQueueItemsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>) consume_Windows_Services_Store_IStoreContext3<D>::GetStoreQueueItemsAsync(param::async_iterable<hstring> const& storeIds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->GetStoreQueueItemsAsync(*(void**)(&storeIds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext3<D>::RequestDownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds, winrt::Windows::Services::Store::StorePackageInstallOptions const& storePackageInstallOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(*(void**)(&storeIds), *(void**)(&storePackageInstallOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStoreContext3<D>::DownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->DownloadAndInstallStorePackagesAsync(*(void**)(&storeIds), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>) consume_Windows_Services_Store_IStoreContext3<D>::RequestUninstallStorePackageAsync(winrt::Windows::ApplicationModel::Package const& package) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->RequestUninstallStorePackageAsync(*(void**)(&package), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>) consume_Windows_Services_Store_IStoreContext3<D>::RequestUninstallStorePackageByStoreIdAsync(param::hstring const& storeId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->RequestUninstallStorePackageByStoreIdAsync(*(void**)(&storeId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>) consume_Windows_Services_Store_IStoreContext3<D>::UninstallStorePackageAsync(winrt::Windows::ApplicationModel::Package const& package) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->UninstallStorePackageAsync(*(void**)(&package), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>) consume_Windows_Services_Store_IStoreContext3<D>::UninstallStorePackageByStoreIdAsync(param::hstring const& storeId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext3)->UninstallStorePackageByStoreIdAsync(*(void**)(&storeId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreRateAndReviewResult>) consume_Windows_Services_Store_IStoreContext4<D>::RequestRateAndReviewAppAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext4)->RequestRateAndReviewAppAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreRateAndReviewResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>) consume_Windows_Services_Store_IStoreContext4<D>::SetInstallOrderForAssociatedStoreQueueItemsAsync(param::async_iterable<winrt::Windows::Services::Store::StoreQueueItem> const& items) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext4)->SetInstallOrderForAssociatedStoreQueueItemsAsync(*(void**)(&items), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>) consume_Windows_Services_Store_IStoreContext5<D>::GetUserPurchaseHistoryAsync(param::async_iterable<hstring> const& productKinds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext5)->GetUserPurchaseHistoryAsync(*(void**)(&productKinds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>) consume_Windows_Services_Store_IStoreContext5<D>::GetAssociatedStoreProductsByInAppOfferTokenAsync(param::async_iterable<hstring> const& inAppOfferTokens) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext5)->GetAssociatedStoreProductsByInAppOfferTokenAsync(*(void**)(&inAppOfferTokens), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreContext5<D>::RequestPurchaseByInAppOfferTokenAsync(param::hstring const& inAppOfferToken) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContext5)->RequestPurchaseByInAppOfferTokenAsync(*(void**)(&inAppOfferToken), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreContext) consume_Windows_Services_Store_IStoreContextStatics<D>::GetDefault() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContextStatics)->GetDefault(&value));
        return winrt::Windows::Services::Store::StoreContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreContext) consume_Windows_Services_Store_IStoreContextStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreContextStatics)->GetForUser(*(void**)(&user), &value));
        return winrt::Windows::Services::Store::StoreContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Services_Store_IStoreImage<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreImage)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreImage<D>::ImagePurposeTag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreImage)->get_ImagePurposeTag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreImage<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreImage)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreImage<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreImage)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreImage<D>::Caption() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreImage)->get_Caption(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreLicense<D>::SkuStoreId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreLicense)->get_SkuStoreId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreLicense<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreLicense)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStoreLicense<D>::ExpirationDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreLicense)->get_ExpirationDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreLicense<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreLicense)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreLicense<D>::InAppOfferToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreLicense)->get_InAppOfferToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStorePackageInstallOptions<D>::AllowForcedAppRestart() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageInstallOptions)->get_AllowForcedAppRestart(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStorePackageInstallOptions<D>::AllowForcedAppRestart(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageInstallOptions)->put_AllowForcedAppRestart(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StorePackageLicense, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageLicense)->add_LicenseLost(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost_revoker consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StorePackageLicense, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, LicenseLost_revoker>(this, LicenseLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageLicense)->remove_LicenseLost(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_Services_Store_IStorePackageLicense<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageLicense)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStorePackageLicense<D>::IsValid() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageLicense)->get_IsValid(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStorePackageLicense<D>::ReleaseLicense() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageLicense)->ReleaseLicense());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) consume_Windows_Services_Store_IStorePackageUpdate<D>::Package() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageUpdate)->get_Package(&value));
        return winrt::Windows::ApplicationModel::Package{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStorePackageUpdate<D>::Mandatory() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageUpdate)->get_Mandatory(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePackageUpdateState) consume_Windows_Services_Store_IStorePackageUpdateResult<D>::OverallState() const
    {
        winrt::Windows::Services::Store::StorePackageUpdateState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageUpdateResult)->get_OverallState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StorePackageUpdateStatus>) consume_Windows_Services_Store_IStorePackageUpdateResult<D>::StorePackageUpdateStatuses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageUpdateResult)->get_StorePackageUpdateStatuses(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StorePackageUpdateStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>) consume_Windows_Services_Store_IStorePackageUpdateResult2<D>::StoreQueueItems() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePackageUpdateResult2)->get_StoreQueueItems(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice<D>::FormattedBasePrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice)->get_FormattedBasePrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice<D>::FormattedPrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice)->get_FormattedPrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStorePrice<D>::IsOnSale() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice)->get_IsOnSale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Services_Store_IStorePrice<D>::SaleEndDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice)->get_SaleEndDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice<D>::CurrencyCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice)->get_CurrencyCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice<D>::FormattedRecurrencePrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice)->get_FormattedRecurrencePrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice2<D>::UnformattedBasePrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice2)->get_UnformattedBasePrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice2<D>::UnformattedPrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice2)->get_UnformattedPrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePrice2<D>::UnformattedRecurrencePrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePrice2)->get_UnformattedRecurrencePrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::StoreId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_StoreId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::ProductKind() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_ProductKind(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreProduct<D>::HasDigitalDownload() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_HasDigitalDownload(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Services_Store_IStoreProduct<D>::Keywords() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Keywords(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreImage>) consume_Windows_Services_Store_IStoreProduct<D>::Images() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Images(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreImage>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreVideo>) consume_Windows_Services_Store_IStoreProduct<D>::Videos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Videos(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreVideo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreSku>) consume_Windows_Services_Store_IStoreProduct<D>::Skus() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Skus(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreSku>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreProduct<D>::IsInUserCollection() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_IsInUserCollection(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePrice) consume_Windows_Services_Store_IStoreProduct<D>::Price() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_Price(&value));
        return winrt::Windows::Services::Store::StorePrice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Services_Store_IStoreProduct<D>::LinkUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_LinkUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Services_Store_IStoreProduct<D>::GetIsAnySkuInstalledAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->GetIsAnySkuInstalledAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreProduct<D>::RequestPurchaseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->RequestPurchaseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreProduct<D>::RequestPurchaseAsync(winrt::Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->RequestPurchaseWithPurchasePropertiesAsync(*(void**)(&storePurchaseProperties), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreProduct<D>::InAppOfferToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProduct)->get_InAppOfferToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Services_Store_IStoreProductOptions<D>::ActionFilters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductOptions)->get_ActionFilters(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreProduct>) consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::Products() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductPagedQueryResult)->get_Products(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreProduct>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::HasMoreResults() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductPagedQueryResult)->get_HasMoreResults(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductPagedQueryResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>) consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::GetNextAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductPagedQueryResult)->GetNextAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreProduct>) consume_Windows_Services_Store_IStoreProductQueryResult<D>::Products() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductQueryResult)->get_Products(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreProduct>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreProductQueryResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductQueryResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreProduct) consume_Windows_Services_Store_IStoreProductResult<D>::Product() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductResult)->get_Product(&value));
        return winrt::Windows::Services::Store::StoreProduct{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreProductResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreProductResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePurchaseProperties<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchaseProperties)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStorePurchaseProperties<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchaseProperties)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStorePurchaseProperties<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchaseProperties)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStorePurchaseProperties<D>::ExtendedJsonData(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchaseProperties)->put_ExtendedJsonData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePurchaseProperties) consume_Windows_Services_Store_IStorePurchasePropertiesFactory<D>::Create(param::hstring const& name) const
    {
        void* storePurchaseProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchasePropertiesFactory)->Create(*(void**)(&name), &storePurchaseProperties));
        return winrt::Windows::Services::Store::StorePurchaseProperties{ storePurchaseProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePurchaseStatus) consume_Windows_Services_Store_IStorePurchaseResult<D>::Status() const
    {
        winrt::Windows::Services::Store::StorePurchaseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchaseResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStorePurchaseResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStorePurchaseResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreQueueItem<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreQueueItem<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreQueueItemKind) consume_Windows_Services_Store_IStoreQueueItem<D>::InstallKind() const
    {
        winrt::Windows::Services::Store::StoreQueueItemKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->get_InstallKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreQueueItemStatus) consume_Windows_Services_Store_IStoreQueueItem<D>::GetCurrentStatus() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->GetCurrentStatus(&result));
        return winrt::Windows::Services::Store::StoreQueueItemStatus{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Store_IStoreQueueItem<D>::Completed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreQueueItem, winrt::Windows::Services::Store::StoreQueueItemCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->add_Completed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Store_IStoreQueueItem<D>::Completed_revoker consume_Windows_Services_Store_IStoreQueueItem<D>::Completed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreQueueItem, winrt::Windows::Services::Store::StoreQueueItemCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStoreQueueItem<D>::Completed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->remove_Completed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreQueueItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->add_StatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged_revoker consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreQueueItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Services_Store_IStoreQueueItem2<D>::CancelInstallAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem2)->CancelInstallAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Services_Store_IStoreQueueItem2<D>::PauseInstallAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem2)->PauseInstallAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Services_Store_IStoreQueueItem2<D>::ResumeInstallAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItem2)->ResumeInstallAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreQueueItemStatus) consume_Windows_Services_Store_IStoreQueueItemCompletedEventArgs<D>::Status() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs)->get_Status(&value));
        return winrt::Windows::Services::Store::StoreQueueItemStatus{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreQueueItemState) consume_Windows_Services_Store_IStoreQueueItemStatus<D>::PackageInstallState() const
    {
        winrt::Windows::Services::Store::StoreQueueItemState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItemStatus)->get_PackageInstallState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreQueueItemExtendedState) consume_Windows_Services_Store_IStoreQueueItemStatus<D>::PackageInstallExtendedState() const
    {
        winrt::Windows::Services::Store::StoreQueueItemExtendedState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItemStatus)->get_PackageInstallExtendedState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePackageUpdateStatus) consume_Windows_Services_Store_IStoreQueueItemStatus<D>::UpdateStatus() const
    {
        winrt::Windows::Services::Store::StorePackageUpdateStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItemStatus)->get_UpdateStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreQueueItemStatus<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreQueueItemStatus)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreRateAndReviewResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreRateAndReviewResult)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::WasUpdated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreRateAndReviewResult)->get_WasUpdated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreRateAndReviewStatus) consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::Status() const
    {
        winrt::Windows::Services::Store::StoreRateAndReviewStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreRateAndReviewResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreSendRequestResult>) consume_Windows_Services_Store_IStoreRequestHelperStatics<D>::SendRequestAsync(winrt::Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreRequestHelperStatics)->SendRequestAsync(*(void**)(&context), requestKind, *(void**)(&parametersAsJson), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreSendRequestResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSendRequestResult<D>::Response() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSendRequestResult)->get_Response(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreSendRequestResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSendRequestResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpStatusCode) consume_Windows_Services_Store_IStoreSendRequestResult2<D>::HttpStatusCode() const
    {
        winrt::Windows::Web::Http::HttpStatusCode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSendRequestResult2)->get_HttpStatusCode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSku<D>::StoreId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_StoreId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSku<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSku<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSku<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreSku<D>::IsTrial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_IsTrial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSku<D>::CustomDeveloperData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_CustomDeveloperData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreImage>) consume_Windows_Services_Store_IStoreSku<D>::Images() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Images(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreImage>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreVideo>) consume_Windows_Services_Store_IStoreSku<D>::Videos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Videos(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreVideo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreAvailability>) consume_Windows_Services_Store_IStoreSku<D>::Availabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Availabilities(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreAvailability>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StorePrice) consume_Windows_Services_Store_IStoreSku<D>::Price() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_Price(&value));
        return winrt::Windows::Services::Store::StorePrice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreSku<D>::ExtendedJsonData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_ExtendedJsonData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreSku<D>::IsInUserCollection() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_IsInUserCollection(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Services_Store_IStoreSku<D>::BundledSkus() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_BundledSkus(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreCollectionData) consume_Windows_Services_Store_IStoreSku<D>::CollectionData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_CollectionData(&value));
        return winrt::Windows::Services::Store::StoreCollectionData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Services_Store_IStoreSku<D>::GetIsInstalledAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->GetIsInstalledAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreSku<D>::RequestPurchaseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->RequestPurchaseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>) consume_Windows_Services_Store_IStoreSku<D>::RequestPurchaseAsync(winrt::Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->RequestPurchaseWithPurchasePropertiesAsync(*(void**)(&storePurchaseProperties), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreSku<D>::IsSubscription() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_IsSubscription(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreSubscriptionInfo) consume_Windows_Services_Store_IStoreSku<D>::SubscriptionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSku)->get_SubscriptionInfo(&value));
        return winrt::Windows::Services::Store::StoreSubscriptionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::BillingPeriod() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSubscriptionInfo)->get_BillingPeriod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreDurationUnit) consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::BillingPeriodUnit() const
    {
        winrt::Windows::Services::Store::StoreDurationUnit value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSubscriptionInfo)->get_BillingPeriodUnit(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::HasTrialPeriod() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSubscriptionInfo)->get_HasTrialPeriod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::TrialPeriod() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSubscriptionInfo)->get_TrialPeriod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreDurationUnit) consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::TrialPeriodUnit() const
    {
        winrt::Windows::Services::Store::StoreDurationUnit value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreSubscriptionInfo)->get_TrialPeriodUnit(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Services_Store_IStoreUninstallStorePackageResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreUninstallStorePackageResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreUninstallStorePackageStatus) consume_Windows_Services_Store_IStoreUninstallStorePackageResult<D>::Status() const
    {
        winrt::Windows::Services::Store::StoreUninstallStorePackageStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreUninstallStorePackageResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Services_Store_IStoreVideo<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreVideo)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreVideo<D>::VideoPurposeTag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreVideo)->get_VideoPurposeTag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreVideo<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreVideo)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Services_Store_IStoreVideo<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreVideo)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Store_IStoreVideo<D>::Caption() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreVideo)->get_Caption(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Store::StoreImage) consume_Windows_Services_Store_IStoreVideo<D>::PreviewImage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Store::IStoreVideo)->get_PreviewImage(&value));
        return winrt::Windows::Services::Store::StoreImage{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreAcquireLicenseResult> : produce_base<D, winrt::Windows::Services::Store::IStoreAcquireLicenseResult>
    {
        int32_t __stdcall get_StorePackageLicense(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePackageLicense>(this->shim().StorePackageLicense());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreAppLicense> : produce_base<D, winrt::Windows::Services::Store::IStoreAppLicense>
    {
        int32_t __stdcall get_SkuStoreId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SkuStoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTrial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AddOnLicenses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreLicense>>(this->shim().AddOnLicenses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrialTimeRemaining(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().TrialTimeRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTrialOwnedByThisUser(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTrialOwnedByThisUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrialUniqueId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TrialUniqueId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreAppLicense2> : produce_base<D, winrt::Windows::Services::Store::IStoreAppLicense2>
    {
        int32_t __stdcall get_IsDiscLicense(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDiscLicense());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreAvailability> : produce_base<D, winrt::Windows::Services::Store::IStoreAvailability>
    {
        int32_t __stdcall get_StoreId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().EndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Price(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePrice>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<winrt::Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult> : produce_base<D, winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LicensableSku(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LicensableSku());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreCanLicenseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreCollectionData> : produce_base<D, winrt::Windows::Services::Store::IStoreCollectionData>
    {
        int32_t __stdcall get_IsTrial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTrial());
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
        int32_t __stdcall get_DeveloperOfferId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeveloperOfferId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AcquiredDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().AcquiredDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().StartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().EndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrialTimeRemaining(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().TrialTimeRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreConsumableResult> : produce_base<D, winrt::Windows::Services::Store::IStoreConsumableResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreConsumableStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrackingId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().TrackingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BalanceRemaining(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().BalanceRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreContext> : produce_base<D, winrt::Windows::Services::Store::IStoreContext>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_OfflineLicensesChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OfflineLicensesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreContext, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OfflineLicensesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OfflineLicensesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetCustomerPurchaseIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetCustomerPurchaseIdAsync(*reinterpret_cast<hstring const*>(&serviceTicket), *reinterpret_cast<hstring const*>(&publisherUserId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCustomerCollectionsIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetCustomerCollectionsIdAsync(*reinterpret_cast<hstring const*>(&serviceTicket), *reinterpret_cast<hstring const*>(&publisherUserId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppLicenseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreAppLicense>>(this->shim().GetAppLicenseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStoreProductForCurrentAppAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductResult>>(this->shim().GetStoreProductForCurrentAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStoreProductsAsync(void* productKinds, void* storeIds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetStoreProductsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAssociatedStoreProductsAsync(void* productKinds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetAssociatedStoreProductsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAssociatedStoreProductsWithPagingAsync(void* productKinds, uint32_t maxItemsToRetrievePerPage, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>>(this->shim().GetAssociatedStoreProductsWithPagingAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), maxItemsToRetrievePerPage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUserCollectionAsync(void* productKinds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetUserCollectionAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUserCollectionWithPagingAsync(void* productKinds, uint32_t maxItemsToRetrievePerPage, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>>(this->shim().GetUserCollectionWithPagingAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), maxItemsToRetrievePerPage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportConsumableFulfillmentAsync(void* productStoreId, uint32_t quantity, winrt::guid trackingId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreConsumableResult>>(this->shim().ReportConsumableFulfillmentAsync(*reinterpret_cast<hstring const*>(&productStoreId), quantity, *reinterpret_cast<winrt::guid const*>(&trackingId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConsumableBalanceRemainingAsync(void* productStoreId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreConsumableResult>>(this->shim().GetConsumableBalanceRemainingAsync(*reinterpret_cast<hstring const*>(&productStoreId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcquireStoreLicenseForOptionalPackageAsync(void* optionalPackage, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreAcquireLicenseResult>>(this->shim().AcquireStoreLicenseForOptionalPackageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Package const*>(&optionalPackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseAsync(void* storeId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<hstring const*>(&storeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseWithPurchasePropertiesAsync(void* storeId, void* storePurchaseProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<winrt::Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppAndOptionalStorePackageUpdatesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StorePackageUpdate>>>(this->shim().GetAppAndOptionalStorePackageUpdatesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestDownloadStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadStorePackageUpdatesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestDownloadAndInstallStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadAndInstallStorePackageUpdatesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestDownloadAndInstallStorePackagesAsync(void* storeIds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadAndInstallStorePackagesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreContext2> : produce_base<D, winrt::Windows::Services::Store::IStoreContext2>
    {
        int32_t __stdcall FindStoreProductForPackageAsync(void* productKinds, void* package, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductResult>>(this->shim().FindStoreProductForPackageAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), *reinterpret_cast<winrt::Windows::ApplicationModel::Package const*>(&package)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreContext3> : produce_base<D, winrt::Windows::Services::Store::IStoreContext3>
    {
        int32_t __stdcall get_CanSilentlyDownloadStorePackageUpdates(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSilentlyDownloadStorePackageUpdates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySilentDownloadStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().TrySilentDownloadStorePackageUpdatesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySilentDownloadAndInstallStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().TrySilentDownloadAndInstallStorePackageUpdatesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CanAcquireStoreLicenseForOptionalPackageAsync(void* optionalPackage, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult>>(this->shim().CanAcquireStoreLicenseForOptionalPackageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Package const*>(&optionalPackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CanAcquireStoreLicenseAsync(void* productStoreId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult>>(this->shim().CanAcquireStoreLicenseAsync(*reinterpret_cast<hstring const*>(&productStoreId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStoreProductsWithOptionsAsync(void* productKinds, void* storeIds, void* storeProductOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetStoreProductsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds), *reinterpret_cast<winrt::Windows::Services::Store::StoreProductOptions const*>(&storeProductOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAssociatedStoreQueueItemsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>>(this->shim().GetAssociatedStoreQueueItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStoreQueueItemsAsync(void* storeIds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>>(this->shim().GetStoreQueueItemsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(void* storeIds, void* storePackageInstallOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadAndInstallStorePackagesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds), *reinterpret_cast<winrt::Windows::Services::Store::StorePackageInstallOptions const*>(&storePackageInstallOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DownloadAndInstallStorePackagesAsync(void* storeIds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Services::Store::StorePackageUpdateResult, winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().DownloadAndInstallStorePackagesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestUninstallStorePackageAsync(void* package, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().RequestUninstallStorePackageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Package const*>(&package)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestUninstallStorePackageByStoreIdAsync(void* storeId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().RequestUninstallStorePackageByStoreIdAsync(*reinterpret_cast<hstring const*>(&storeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UninstallStorePackageAsync(void* package, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().UninstallStorePackageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Package const*>(&package)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UninstallStorePackageByStoreIdAsync(void* storeId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().UninstallStorePackageByStoreIdAsync(*reinterpret_cast<hstring const*>(&storeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreContext4> : produce_base<D, winrt::Windows::Services::Store::IStoreContext4>
    {
        int32_t __stdcall RequestRateAndReviewAppAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreRateAndReviewResult>>(this->shim().RequestRateAndReviewAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetInstallOrderForAssociatedStoreQueueItemsAsync(void* items, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>>(this->shim().SetInstallOrderForAssociatedStoreQueueItemsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Services::Store::StoreQueueItem> const*>(&items)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreContext5> : produce_base<D, winrt::Windows::Services::Store::IStoreContext5>
    {
        int32_t __stdcall GetUserPurchaseHistoryAsync(void* productKinds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetUserPurchaseHistoryAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAssociatedStoreProductsByInAppOfferTokenAsync(void* inAppOfferTokens, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetAssociatedStoreProductsByInAppOfferTokenAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&inAppOfferTokens)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseByInAppOfferTokenAsync(void* inAppOfferToken, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseByInAppOfferTokenAsync(*reinterpret_cast<hstring const*>(&inAppOfferToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreContextStatics> : produce_base<D, winrt::Windows::Services::Store::IStoreContextStatics>
    {
        int32_t __stdcall GetDefault(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreContext>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForUser(void* user, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreContext>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreImage> : produce_base<D, winrt::Windows::Services::Store::IStoreImage>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ImagePurposeTag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ImagePurposeTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Caption(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreLicense> : produce_base<D, winrt::Windows::Services::Store::IStoreLicense>
    {
        int32_t __stdcall get_SkuStoreId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SkuStoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InAppOfferToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InAppOfferToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePackageInstallOptions> : produce_base<D, winrt::Windows::Services::Store::IStorePackageInstallOptions>
    {
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
    struct produce<D, winrt::Windows::Services::Store::IStorePackageLicense> : produce_base<D, winrt::Windows::Services::Store::IStorePackageLicense>
    {
        int32_t __stdcall add_LicenseLost(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LicenseLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StorePackageLicense, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LicenseLost(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LicenseLost(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsValid(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsValid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleaseLicense() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseLicense();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePackageUpdate> : produce_base<D, winrt::Windows::Services::Store::IStorePackageUpdate>
    {
        int32_t __stdcall get_Package(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mandatory(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Mandatory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePackageUpdateResult> : produce_base<D, winrt::Windows::Services::Store::IStorePackageUpdateResult>
    {
        int32_t __stdcall get_OverallState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePackageUpdateState>(this->shim().OverallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StorePackageUpdateStatuses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().StorePackageUpdateStatuses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePackageUpdateResult2> : produce_base<D, winrt::Windows::Services::Store::IStorePackageUpdateResult2>
    {
        int32_t __stdcall get_StoreQueueItems(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreQueueItem>>(this->shim().StoreQueueItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePrice> : produce_base<D, winrt::Windows::Services::Store::IStorePrice>
    {
        int32_t __stdcall get_FormattedBasePrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormattedBasePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FormattedPrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormattedPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOnSale(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOnSale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SaleEndDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().SaleEndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrencyCode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CurrencyCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FormattedRecurrencePrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormattedRecurrencePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePrice2> : produce_base<D, winrt::Windows::Services::Store::IStorePrice2>
    {
        int32_t __stdcall get_UnformattedBasePrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnformattedBasePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnformattedPrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnformattedPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnformattedRecurrencePrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnformattedRecurrencePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreProduct> : produce_base<D, winrt::Windows::Services::Store::IStoreProduct>
    {
        int32_t __stdcall get_StoreId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
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
        int32_t __stdcall get_ProductKind(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasDigitalDownload(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasDigitalDownload());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Keywords(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Images(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreImage>>(this->shim().Images());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Videos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreVideo>>(this->shim().Videos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Skus(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreSku>>(this->shim().Skus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInUserCollection(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInUserCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Price(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePrice>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LinkUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().LinkUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsAnySkuInstalledAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAnySkuInstalledAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<winrt::Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InAppOfferToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InAppOfferToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreProductOptions> : produce_base<D, winrt::Windows::Services::Store::IStoreProductOptions>
    {
        int32_t __stdcall get_ActionFilters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ActionFilters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreProductPagedQueryResult> : produce_base<D, winrt::Windows::Services::Store::IStoreProductPagedQueryResult>
    {
        int32_t __stdcall get_Products(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreProduct>>(this->shim().Products());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasMoreResults(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasMoreResults());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNextAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreProductPagedQueryResult>>(this->shim().GetNextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreProductQueryResult> : produce_base<D, winrt::Windows::Services::Store::IStoreProductQueryResult>
    {
        int32_t __stdcall get_Products(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Services::Store::StoreProduct>>(this->shim().Products());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreProductResult> : produce_base<D, winrt::Windows::Services::Store::IStoreProductResult>
    {
        int32_t __stdcall get_Product(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreProduct>(this->shim().Product());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePurchaseProperties> : produce_base<D, winrt::Windows::Services::Store::IStorePurchaseProperties>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExtendedJsonData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExtendedJsonData(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePurchasePropertiesFactory> : produce_base<D, winrt::Windows::Services::Store::IStorePurchasePropertiesFactory>
    {
        int32_t __stdcall Create(void* name, void** storePurchaseProperties) noexcept final try
        {
            clear_abi(storePurchaseProperties);
            typename D::abi_guard guard(this->shim());
            *storePurchaseProperties = detach_from<winrt::Windows::Services::Store::StorePurchaseProperties>(this->shim().Create(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStorePurchaseResult> : produce_base<D, winrt::Windows::Services::Store::IStorePurchaseResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePurchaseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreQueueItem> : produce_base<D, winrt::Windows::Services::Store::IStoreQueueItem>
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
        int32_t __stdcall get_InstallKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreQueueItemKind>(this->shim().InstallKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentStatus(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Store::StoreQueueItemStatus>(this->shim().GetCurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Completed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreQueueItem, winrt::Windows::Services::Store::StoreQueueItemCompletedEventArgs> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Store::StoreQueueItem, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
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
    struct produce<D, winrt::Windows::Services::Store::IStoreQueueItem2> : produce_base<D, winrt::Windows::Services::Store::IStoreQueueItem2>
    {
        int32_t __stdcall CancelInstallAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CancelInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseInstallAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().PauseInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResumeInstallAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ResumeInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs> : produce_base<D, winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs>
    {
        int32_t __stdcall get_Status(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreQueueItemStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreQueueItemStatus> : produce_base<D, winrt::Windows::Services::Store::IStoreQueueItemStatus>
    {
        int32_t __stdcall get_PackageInstallState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreQueueItemState>(this->shim().PackageInstallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PackageInstallExtendedState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreQueueItemExtendedState>(this->shim().PackageInstallExtendedState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpdateStatus(struct struct_Windows_Services_Store_StorePackageUpdateStatus* value) noexcept final try
        {
            zero_abi<winrt::Windows::Services::Store::StorePackageUpdateStatus>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePackageUpdateStatus>(this->shim().UpdateStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreRateAndReviewResult> : produce_base<D, winrt::Windows::Services::Store::IStoreRateAndReviewResult>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WasUpdated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasUpdated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreRateAndReviewStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreRequestHelperStatics> : produce_base<D, winrt::Windows::Services::Store::IStoreRequestHelperStatics>
    {
        int32_t __stdcall SendRequestAsync(void* context, uint32_t requestKind, void* parametersAsJson, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StoreSendRequestResult>>(this->shim().SendRequestAsync(*reinterpret_cast<winrt::Windows::Services::Store::StoreContext const*>(&context), requestKind, *reinterpret_cast<hstring const*>(&parametersAsJson)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreSendRequestResult> : produce_base<D, winrt::Windows::Services::Store::IStoreSendRequestResult>
    {
        int32_t __stdcall get_Response(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreSendRequestResult2> : produce_base<D, winrt::Windows::Services::Store::IStoreSendRequestResult2>
    {
        int32_t __stdcall get_HttpStatusCode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpStatusCode>(this->shim().HttpStatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreSku> : produce_base<D, winrt::Windows::Services::Store::IStoreSku>
    {
        int32_t __stdcall get_StoreId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
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
        int32_t __stdcall get_IsTrial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomDeveloperData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CustomDeveloperData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Images(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreImage>>(this->shim().Images());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Videos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreVideo>>(this->shim().Videos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Availabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Store::StoreAvailability>>(this->shim().Availabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Price(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StorePrice>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedJsonData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInUserCollection(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInUserCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BundledSkus(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().BundledSkus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CollectionData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreCollectionData>(this->shim().CollectionData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsInstalledAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsInstalledAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<winrt::Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSubscription(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSubscription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubscriptionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreSubscriptionInfo>(this->shim().SubscriptionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreSubscriptionInfo> : produce_base<D, winrt::Windows::Services::Store::IStoreSubscriptionInfo>
    {
        int32_t __stdcall get_BillingPeriod(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().BillingPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BillingPeriodUnit(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreDurationUnit>(this->shim().BillingPeriodUnit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasTrialPeriod(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasTrialPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrialPeriod(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TrialPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrialPeriodUnit(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreDurationUnit>(this->shim().TrialPeriodUnit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreUninstallStorePackageResult> : produce_base<D, winrt::Windows::Services::Store::IStoreUninstallStorePackageResult>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreUninstallStorePackageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Store::IStoreVideo> : produce_base<D, winrt::Windows::Services::Store::IStoreVideo>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoPurposeTag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoPurposeTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Caption(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviewImage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Store::StoreImage>(this->shim().PreviewImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Services::Store
{
    inline auto StoreContext::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Services::Store::StoreContext(*)(IStoreContextStatics const&), StoreContext, IStoreContextStatics>([](IStoreContextStatics const& f) { return f.GetDefault(); });
    }
    inline auto StoreContext::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<StoreContext, IStoreContextStatics>([&](IStoreContextStatics const& f) { return f.GetForUser(user); });
    }
    inline StorePackageInstallOptions::StorePackageInstallOptions() :
        StorePackageInstallOptions(impl::call_factory_cast<StorePackageInstallOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), StorePackageInstallOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorePackageInstallOptions>(); }))
    {
    }
    inline StoreProductOptions::StoreProductOptions() :
        StoreProductOptions(impl::call_factory_cast<StoreProductOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), StoreProductOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StoreProductOptions>(); }))
    {
    }
    inline StorePurchaseProperties::StorePurchaseProperties() :
        StorePurchaseProperties(impl::call_factory_cast<StorePurchaseProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), StorePurchaseProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorePurchaseProperties>(); }))
    {
    }
    inline StorePurchaseProperties::StorePurchaseProperties(param::hstring const& name) :
        StorePurchaseProperties(impl::call_factory<StorePurchaseProperties, IStorePurchasePropertiesFactory>([&](IStorePurchasePropertiesFactory const& f) { return f.Create(name); }))
    {
    }
    inline auto StoreRequestHelper::SendRequestAsync(winrt::Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson)
    {
        return impl::call_factory<StoreRequestHelper, IStoreRequestHelperStatics>([&](IStoreRequestHelperStatics const& f) { return f.SendRequestAsync(context, requestKind, parametersAsJson); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Services::Store::IStoreAcquireLicenseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreAppLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreAppLicense2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreAvailability> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreCollectionData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreConsumableResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreContext2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreContext3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreContext4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreContext5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreContextStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreImage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePackageInstallOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePackageLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePackageUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePackageUpdateResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePackageUpdateResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePrice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePrice2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreProduct> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreProductOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreProductPagedQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreProductQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreProductResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePurchaseProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePurchasePropertiesFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStorePurchaseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItem2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItemStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreRateAndReviewResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreRequestHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreSendRequestResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreSendRequestResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreSku> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreSubscriptionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreUninstallStorePackageResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::IStoreVideo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreAcquireLicenseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreAppLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreAvailability> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreCollectionData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreConsumableResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreImage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePackageInstallOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePackageLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePackageUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePackageUpdateResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePrice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreProduct> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreProductOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreProductPagedQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreProductQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreProductResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePurchaseProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StorePurchaseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreQueueItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreQueueItemCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreQueueItemStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreRateAndReviewResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreRequestHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreSendRequestResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreSku> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreSubscriptionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreUninstallStorePackageResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Store::StoreVideo> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
