// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_H
#define WINRT_Windows_ApplicationModel_Store_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::LicenseInformation) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::LicenseInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->get_LicenseInformation(&value));
        return winrt::Windows::ApplicationModel::Store::LicenseInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::LinkUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->get_LinkUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::AppId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->get_AppId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::RequestAppPurchaseAsync(bool includeReceipt) const
    {
        void* requestAppPurchaseOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->RequestAppPurchaseAsync(includeReceipt, &requestAppPurchaseOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ requestAppPurchaseOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt) const
    {
        void* requestProductPurchaseOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->RequestProductPurchaseAsync(*(void**)(&productId), includeReceipt, &requestProductPurchaseOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ requestProductPurchaseOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::LoadListingInformationAsync() const
    {
        void* loadListingOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->LoadListingInformationAsync(&loadListingOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>{ loadListingOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::GetAppReceiptAsync() const
    {
        void* appReceiptOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->GetAppReceiptAsync(&appReceiptOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ appReceiptOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentApp<D>::GetProductReceiptAsync(param::hstring const& productId) const
    {
        void* getProductReceiptOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp)->GetProductReceiptAsync(*(void**)(&productId), &getProductReceiptOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ getProductReceiptOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentApp2Statics<D>::GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics)->GetCustomerPurchaseIdAsync(*(void**)(&serviceTicket), *(void**)(&publisherUserId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentApp2Statics<D>::GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics)->GetCustomerCollectionsIdAsync(*(void**)(&serviceTicket), *(void**)(&publisherUserId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::LicenseInformation) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::LicenseInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->get_LicenseInformation(&value));
        return winrt::Windows::ApplicationModel::Store::LicenseInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::LinkUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->get_LinkUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::AppId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->get_AppId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::RequestAppPurchaseAsync(bool includeReceipt) const
    {
        void* requestAppPurchaseOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->RequestAppPurchaseAsync(includeReceipt, &requestAppPurchaseOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ requestAppPurchaseOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt) const
    {
        void* requestProductPurchaseOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->RequestProductPurchaseAsync(*(void**)(&productId), includeReceipt, &requestProductPurchaseOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ requestProductPurchaseOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::LoadListingInformationAsync() const
    {
        void* loadListingOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->LoadListingInformationAsync(&loadListingOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>{ loadListingOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::GetAppReceiptAsync() const
    {
        void* appReceiptOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->GetAppReceiptAsync(&appReceiptOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ appReceiptOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::GetProductReceiptAsync(param::hstring const& productId) const
    {
        void* getProductReceiptOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->GetProductReceiptAsync(*(void**)(&productId), &getProductReceiptOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ getProductReceiptOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Store_ICurrentAppSimulator<D>::ReloadSimulatorAsync(winrt::Windows::Storage::StorageFile const& simulatorSettingsFile) const
    {
        void* reloadSimulatorOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator)->ReloadSimulatorAsync(*(void**)(&simulatorSettingsFile), &reloadSimulatorOperation));
        return winrt::Windows::Foundation::IAsyncAction{ reloadSimulatorOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorStaticsWithFiltering<D>::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds) const
    {
        void* loadListingOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering)->LoadListingInformationByProductIdsAsync(*(void**)(&productIds), &loadListingOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>{ loadListingOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorStaticsWithFiltering<D>::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords) const
    {
        void* loadListingOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering)->LoadListingInformationByKeywordsAsync(*(void**)(&keywords), &loadListingOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>{ loadListingOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithCampaignId<D>::GetAppPurchaseCampaignIdAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId)->GetAppPurchaseCampaignIdAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::FulfillmentResult>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId) const
    {
        void* reportConsumableFulfillmentOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->ReportConsumableFulfillmentAsync(*(void**)(&productId), impl::bind_in(transactionId), &reportConsumableFulfillmentOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::FulfillmentResult>{ reportConsumableFulfillmentOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId) const
    {
        void* requestProductPurchaseWithResultsOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->RequestProductPurchaseWithResultsAsync(*(void**)(&productId), &requestProductPurchaseWithResultsOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>{ requestProductPurchaseWithResultsOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties) const
    {
        void* requestProductPurchaseWithDisplayPropertiesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->RequestProductPurchaseWithDisplayPropertiesAsync(*(void**)(&productId), *(void**)(&offerId), *(void**)(&displayProperties), &requestProductPurchaseWithDisplayPropertiesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>{ requestProductPurchaseWithDisplayPropertiesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>) consume_Windows_ApplicationModel_Store_ICurrentAppSimulatorWithConsumables<D>::GetUnfulfilledConsumablesAsync() const
    {
        void* getUnfulfilledConsumablesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables)->GetUnfulfilledConsumablesAsync(&getUnfulfilledConsumablesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>{ getUnfulfilledConsumablesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>) consume_Windows_ApplicationModel_Store_ICurrentAppStaticsWithFiltering<D>::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds) const
    {
        void* loadListingOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering)->LoadListingInformationByProductIdsAsync(*(void**)(&productIds), &loadListingOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>{ loadListingOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>) consume_Windows_ApplicationModel_Store_ICurrentAppStaticsWithFiltering<D>::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords) const
    {
        void* loadListingOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering)->LoadListingInformationByKeywordsAsync(*(void**)(&keywords), &loadListingOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>{ loadListingOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_ICurrentAppStaticsWithFiltering<D>::ReportProductFulfillment(param::hstring const& productId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering)->ReportProductFulfillment(*(void**)(&productId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Store_ICurrentAppWithCampaignId<D>::GetAppPurchaseCampaignIdAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppWithCampaignId)->GetAppPurchaseCampaignIdAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::FulfillmentResult>) consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId) const
    {
        void* reportConsumableFulfillmentOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->ReportConsumableFulfillmentAsync(*(void**)(&productId), impl::bind_in(transactionId), &reportConsumableFulfillmentOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::FulfillmentResult>{ reportConsumableFulfillmentOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>) consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId) const
    {
        void* requestProductPurchaseWithResultsOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->RequestProductPurchaseWithResultsAsync(*(void**)(&productId), &requestProductPurchaseWithResultsOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>{ requestProductPurchaseWithResultsOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>) consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties) const
    {
        void* requestProductPurchaseWithDisplayPropertiesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->RequestProductPurchaseWithDisplayPropertiesAsync(*(void**)(&productId), *(void**)(&offerId), *(void**)(&displayProperties), &requestProductPurchaseWithDisplayPropertiesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>{ requestProductPurchaseWithDisplayPropertiesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>) consume_Windows_ApplicationModel_Store_ICurrentAppWithConsumables<D>::GetUnfulfilledConsumablesAsync() const
    {
        void* getUnfulfilledConsumablesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables)->GetUnfulfilledConsumablesAsync(&getUnfulfilledConsumablesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>{ getUnfulfilledConsumablesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::ProductLicense>) consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::ProductLicenses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ILicenseInformation)->get_ProductLicenses(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::ProductLicense>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ILicenseInformation)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::IsTrial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ILicenseInformation)->get_IsTrial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::ExpirationDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ILicenseInformation)->get_ExpirationDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged(winrt::Windows::ApplicationModel::Store::LicenseChangedEventHandler const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ILicenseInformation)->add_LicenseChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged_revoker consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged(auto_revoke_t, winrt::Windows::ApplicationModel::Store::LicenseChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, LicenseChanged_revoker>(this, LicenseChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_ILicenseInformation<D>::LicenseChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::ILicenseInformation)->remove_LicenseChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IListingInformation<D>::CurrentMarket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation)->get_CurrentMarket(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IListingInformation<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::ProductListing>) consume_Windows_ApplicationModel_Store_IListingInformation<D>::ProductListings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation)->get_ProductListings(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::ProductListing>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IListingInformation<D>::FormattedPrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation)->get_FormattedPrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IListingInformation<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Store_IListingInformation<D>::AgeRating() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation)->get_AgeRating(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IListingInformation2<D>::FormattedBasePrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation2)->get_FormattedBasePrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Store_IListingInformation2<D>::SaleEndDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation2)->get_SaleEndDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_IListingInformation2<D>::IsOnSale() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation2)->get_IsOnSale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IListingInformation2<D>::CurrencyCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IListingInformation2)->get_CurrencyCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductLicense<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductLicense)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_IProductLicense<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductLicense)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Store_IProductLicense<D>::ExpirationDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductLicense)->get_ExpirationDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_IProductLicenseWithFulfillment<D>::IsConsumable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment)->get_IsConsumable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListing<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListing<D>::FormattedPrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing)->get_FormattedPrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListing<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListing2<D>::FormattedBasePrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing2)->get_FormattedBasePrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Store_IProductListing2<D>::SaleEndDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing2)->get_SaleEndDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_IProductListing2<D>::IsOnSale() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing2)->get_IsOnSale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListing2<D>::CurrencyCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListing2)->get_CurrencyCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::ProductType) consume_Windows_ApplicationModel_Store_IProductListingWithConsumables<D>::ProductType() const
    {
        winrt::Windows::ApplicationModel::Store::ProductType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListingWithConsumables)->get_ProductType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<hstring>) consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::Keywords() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_Keywords(&value));
        return winrt::Windows::Foundation::Collections::IIterable<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::ProductType) consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::ProductType() const
    {
        winrt::Windows::ApplicationModel::Store::ProductType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_ProductType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Store_IProductListingWithMetadata<D>::ImageUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata)->get_ImageUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Image() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->get_Image(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayProperties<D>::Image(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties)->put_Image(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties) consume_Windows_ApplicationModel_Store_IProductPurchaseDisplayPropertiesFactory<D>::CreateProductPurchaseDisplayProperties(param::hstring const& name) const
    {
        void* displayProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory)->CreateProductPurchaseDisplayProperties(*(void**)(&name), &displayProperties));
        return winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties{ displayProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::ProductPurchaseStatus) consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Store::ProductPurchaseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IPurchaseResults)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::TransactionId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IPurchaseResults)->get_TransactionId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::ReceiptXml() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IPurchaseResults)->get_ReceiptXml(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IPurchaseResults<D>::OfferId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IPurchaseResults)->get_OfferId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IUnfulfilledConsumable<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_ApplicationModel_Store_IUnfulfilledConsumable<D>::TransactionId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable)->get_TransactionId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_IUnfulfilledConsumable<D>::OfferId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable)->get_OfferId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::ApplicationModel::Store::LicenseChangedEventHandler, H> final : implements_delegate<winrt::Windows::ApplicationModel::Store::LicenseChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::ApplicationModel::Store::LicenseChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke() noexcept final try
        {
            (*this)();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentApp> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentApp>
    {
        int32_t __stdcall get_LicenseInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::LicenseInformation>(this->shim().LicenseInformation());
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
        int32_t __stdcall get_AppId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAppPurchaseAsync(bool includeReceipt, void** requestAppPurchaseOperation) noexcept final try
        {
            clear_abi(requestAppPurchaseOperation);
            typename D::abi_guard guard(this->shim());
            *requestAppPurchaseOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestAppPurchaseAsync(includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestProductPurchaseAsync(void* productId, bool includeReceipt, void** requestProductPurchaseOperation) noexcept final try
        {
            clear_abi(requestProductPurchaseOperation);
            typename D::abi_guard guard(this->shim());
            *requestProductPurchaseOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadListingInformationAsync(void** loadListingOperation) noexcept final try
        {
            clear_abi(loadListingOperation);
            typename D::abi_guard guard(this->shim());
            *loadListingOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppReceiptAsync(void** appReceiptOperation) noexcept final try
        {
            clear_abi(appReceiptOperation);
            typename D::abi_guard guard(this->shim());
            *appReceiptOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppReceiptAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetProductReceiptAsync(void* productId, void** getProductReceiptOperation) noexcept final try
        {
            clear_abi(getProductReceiptOperation);
            typename D::abi_guard guard(this->shim());
            *getProductReceiptOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetProductReceiptAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics>
    {
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator>
    {
        int32_t __stdcall get_LicenseInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::LicenseInformation>(this->shim().LicenseInformation());
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
        int32_t __stdcall get_AppId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAppPurchaseAsync(bool includeReceipt, void** requestAppPurchaseOperation) noexcept final try
        {
            clear_abi(requestAppPurchaseOperation);
            typename D::abi_guard guard(this->shim());
            *requestAppPurchaseOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestAppPurchaseAsync(includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestProductPurchaseAsync(void* productId, bool includeReceipt, void** requestProductPurchaseOperation) noexcept final try
        {
            clear_abi(requestProductPurchaseOperation);
            typename D::abi_guard guard(this->shim());
            *requestProductPurchaseOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), includeReceipt));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadListingInformationAsync(void** loadListingOperation) noexcept final try
        {
            clear_abi(loadListingOperation);
            typename D::abi_guard guard(this->shim());
            *loadListingOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppReceiptAsync(void** appReceiptOperation) noexcept final try
        {
            clear_abi(appReceiptOperation);
            typename D::abi_guard guard(this->shim());
            *appReceiptOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppReceiptAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetProductReceiptAsync(void* productId, void** getProductReceiptOperation) noexcept final try
        {
            clear_abi(getProductReceiptOperation);
            typename D::abi_guard guard(this->shim());
            *getProductReceiptOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetProductReceiptAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReloadSimulatorAsync(void* simulatorSettingsFile, void** reloadSimulatorOperation) noexcept final try
        {
            clear_abi(reloadSimulatorOperation);
            typename D::abi_guard guard(this->shim());
            *reloadSimulatorOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReloadSimulatorAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&simulatorSettingsFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering>
    {
        int32_t __stdcall LoadListingInformationByProductIdsAsync(void* productIds, void** loadListingOperation) noexcept final try
        {
            clear_abi(loadListingOperation);
            typename D::abi_guard guard(this->shim());
            *loadListingOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByProductIdsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadListingInformationByKeywordsAsync(void* keywords, void** loadListingOperation) noexcept final try
        {
            clear_abi(loadListingOperation);
            typename D::abi_guard guard(this->shim());
            *loadListingOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByKeywordsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&keywords)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId>
    {
        int32_t __stdcall GetAppPurchaseCampaignIdAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppPurchaseCampaignIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables>
    {
        int32_t __stdcall ReportConsumableFulfillmentAsync(void* productId, winrt::guid transactionId, void** reportConsumableFulfillmentOperation) noexcept final try
        {
            clear_abi(reportConsumableFulfillmentOperation);
            typename D::abi_guard guard(this->shim());
            *reportConsumableFulfillmentOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::FulfillmentResult>>(this->shim().ReportConsumableFulfillmentAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<winrt::guid const*>(&transactionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestProductPurchaseWithResultsAsync(void* productId, void** requestProductPurchaseWithResultsOperation) noexcept final try
        {
            clear_abi(requestProductPurchaseWithResultsOperation);
            typename D::abi_guard guard(this->shim());
            *requestProductPurchaseWithResultsOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestProductPurchaseWithDisplayPropertiesAsync(void* productId, void* offerId, void* displayProperties, void** requestProductPurchaseWithDisplayPropertiesOperation) noexcept final try
        {
            clear_abi(requestProductPurchaseWithDisplayPropertiesOperation);
            typename D::abi_guard guard(this->shim());
            *requestProductPurchaseWithDisplayPropertiesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&offerId), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const*>(&displayProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUnfulfilledConsumablesAsync(void** getUnfulfilledConsumablesOperation) noexcept final try
        {
            clear_abi(getUnfulfilledConsumablesOperation);
            typename D::abi_guard guard(this->shim());
            *getUnfulfilledConsumablesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>>(this->shim().GetUnfulfilledConsumablesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering>
    {
        int32_t __stdcall LoadListingInformationByProductIdsAsync(void* productIds, void** loadListingOperation) noexcept final try
        {
            clear_abi(loadListingOperation);
            typename D::abi_guard guard(this->shim());
            *loadListingOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByProductIdsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&productIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadListingInformationByKeywordsAsync(void* keywords, void** loadListingOperation) noexcept final try
        {
            clear_abi(loadListingOperation);
            typename D::abi_guard guard(this->shim());
            *loadListingOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>>(this->shim().LoadListingInformationByKeywordsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&keywords)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportProductFulfillment(void* productId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportProductFulfillment(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppWithCampaignId> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppWithCampaignId>
    {
        int32_t __stdcall GetAppPurchaseCampaignIdAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAppPurchaseCampaignIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables> : produce_base<D, winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables>
    {
        int32_t __stdcall ReportConsumableFulfillmentAsync(void* productId, winrt::guid transactionId, void** reportConsumableFulfillmentOperation) noexcept final try
        {
            clear_abi(reportConsumableFulfillmentOperation);
            typename D::abi_guard guard(this->shim());
            *reportConsumableFulfillmentOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::FulfillmentResult>>(this->shim().ReportConsumableFulfillmentAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<winrt::guid const*>(&transactionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestProductPurchaseWithResultsAsync(void* productId, void** requestProductPurchaseWithResultsOperation) noexcept final try
        {
            clear_abi(requestProductPurchaseWithResultsOperation);
            typename D::abi_guard guard(this->shim());
            *requestProductPurchaseWithResultsOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestProductPurchaseWithDisplayPropertiesAsync(void* productId, void* offerId, void* displayProperties, void** requestProductPurchaseWithDisplayPropertiesOperation) noexcept final try
        {
            clear_abi(requestProductPurchaseWithDisplayPropertiesOperation);
            typename D::abi_guard guard(this->shim());
            *requestProductPurchaseWithDisplayPropertiesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::PurchaseResults>>(this->shim().RequestProductPurchaseAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&offerId), *reinterpret_cast<winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const*>(&displayProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUnfulfilledConsumablesAsync(void** getUnfulfilledConsumablesOperation) noexcept final try
        {
            clear_abi(getUnfulfilledConsumablesOperation);
            typename D::abi_guard guard(this->shim());
            *getUnfulfilledConsumablesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>>(this->shim().GetUnfulfilledConsumablesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::ILicenseInformation> : produce_base<D, winrt::Windows::ApplicationModel::Store::ILicenseInformation>
    {
        int32_t __stdcall get_ProductLicenses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::ProductLicense>>(this->shim().ProductLicenses());
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
        int32_t __stdcall add_LicenseChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().LicenseChanged(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::LicenseChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LicenseChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LicenseChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IListingInformation> : produce_base<D, winrt::Windows::ApplicationModel::Store::IListingInformation>
    {
        int32_t __stdcall get_CurrentMarket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CurrentMarket());
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
        int32_t __stdcall get_ProductListings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::ProductListing>>(this->shim().ProductListings());
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
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AgeRating(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AgeRating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IListingInformation2> : produce_base<D, winrt::Windows::ApplicationModel::Store::IListingInformation2>
    {
        int32_t __stdcall get_FormattedBasePrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormattedBasePrice());
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
        int32_t __stdcall get_IsOnSale(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOnSale());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductLicense> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductLicense>
    {
        int32_t __stdcall get_ProductId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductId());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment>
    {
        int32_t __stdcall get_IsConsumable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConsumable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductListing> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductListing>
    {
        int32_t __stdcall get_ProductId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductId());
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
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductListing2> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductListing2>
    {
        int32_t __stdcall get_FormattedBasePrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormattedBasePrice());
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
        int32_t __stdcall get_IsOnSale(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOnSale());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductListingWithConsumables> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductListingWithConsumables>
    {
        int32_t __stdcall get_ProductType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::ProductType>(this->shim().ProductType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata>
    {
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Keywords(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IIterable<hstring>>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProductType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::ProductType>(this->shim().ProductType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ImageUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ImageUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties>
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
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Image(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Image(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Image(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory> : produce_base<D, winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory>
    {
        int32_t __stdcall CreateProductPurchaseDisplayProperties(void* name, void** displayProperties) noexcept final try
        {
            clear_abi(displayProperties);
            typename D::abi_guard guard(this->shim());
            *displayProperties = detach_from<winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties>(this->shim().CreateProductPurchaseDisplayProperties(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IPurchaseResults> : produce_base<D, winrt::Windows::ApplicationModel::Store::IPurchaseResults>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::ProductPurchaseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransactionId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().TransactionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReceiptXml(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ReceiptXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OfferId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OfferId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable> : produce_base<D, winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable>
    {
        int32_t __stdcall get_ProductId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransactionId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().TransactionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OfferId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OfferId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store
{
    inline auto CurrentApp::LicenseInformation()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Store::LicenseInformation(*)(ICurrentApp const&), CurrentApp, ICurrentApp>([](ICurrentApp const& f) { return f.LicenseInformation(); });
    }
    inline auto CurrentApp::LinkUri()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Uri(*)(ICurrentApp const&), CurrentApp, ICurrentApp>([](ICurrentApp const& f) { return f.LinkUri(); });
    }
    inline auto CurrentApp::AppId()
    {
        return impl::call_factory_cast<winrt::guid(*)(ICurrentApp const&), CurrentApp, ICurrentApp>([](ICurrentApp const& f) { return f.AppId(); });
    }
    inline auto CurrentApp::RequestAppPurchaseAsync(bool includeReceipt)
    {
        return impl::call_factory<CurrentApp, ICurrentApp>([&](ICurrentApp const& f) { return f.RequestAppPurchaseAsync(includeReceipt); });
    }
    inline auto CurrentApp::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt)
    {
        return impl::call_factory<CurrentApp, ICurrentApp>([&](ICurrentApp const& f) { return f.RequestProductPurchaseAsync(productId, includeReceipt); });
    }
    inline auto CurrentApp::LoadListingInformationAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>(*)(ICurrentApp const&), CurrentApp, ICurrentApp>([](ICurrentApp const& f) { return f.LoadListingInformationAsync(); });
    }
    inline auto CurrentApp::GetAppReceiptAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<hstring>(*)(ICurrentApp const&), CurrentApp, ICurrentApp>([](ICurrentApp const& f) { return f.GetAppReceiptAsync(); });
    }
    inline auto CurrentApp::GetProductReceiptAsync(param::hstring const& productId)
    {
        return impl::call_factory<CurrentApp, ICurrentApp>([&](ICurrentApp const& f) { return f.GetProductReceiptAsync(productId); });
    }
    inline auto CurrentApp::GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId)
    {
        return impl::call_factory<CurrentApp, ICurrentApp2Statics>([&](ICurrentApp2Statics const& f) { return f.GetCustomerPurchaseIdAsync(serviceTicket, publisherUserId); });
    }
    inline auto CurrentApp::GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId)
    {
        return impl::call_factory<CurrentApp, ICurrentApp2Statics>([&](ICurrentApp2Statics const& f) { return f.GetCustomerCollectionsIdAsync(serviceTicket, publisherUserId); });
    }
    inline auto CurrentApp::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds)
    {
        return impl::call_factory<CurrentApp, ICurrentAppStaticsWithFiltering>([&](ICurrentAppStaticsWithFiltering const& f) { return f.LoadListingInformationByProductIdsAsync(productIds); });
    }
    inline auto CurrentApp::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords)
    {
        return impl::call_factory<CurrentApp, ICurrentAppStaticsWithFiltering>([&](ICurrentAppStaticsWithFiltering const& f) { return f.LoadListingInformationByKeywordsAsync(keywords); });
    }
    inline auto CurrentApp::ReportProductFulfillment(param::hstring const& productId)
    {
        impl::call_factory<CurrentApp, ICurrentAppStaticsWithFiltering>([&](ICurrentAppStaticsWithFiltering const& f) { return f.ReportProductFulfillment(productId); });
    }
    inline auto CurrentApp::GetAppPurchaseCampaignIdAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<hstring>(*)(ICurrentAppWithCampaignId const&), CurrentApp, ICurrentAppWithCampaignId>([](ICurrentAppWithCampaignId const& f) { return f.GetAppPurchaseCampaignIdAsync(); });
    }
    inline auto CurrentApp::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId)
    {
        return impl::call_factory<CurrentApp, ICurrentAppWithConsumables>([&](ICurrentAppWithConsumables const& f) { return f.ReportConsumableFulfillmentAsync(productId, transactionId); });
    }
    inline auto CurrentApp::RequestProductPurchaseAsync(param::hstring const& productId)
    {
        return impl::call_factory<CurrentApp, ICurrentAppWithConsumables>([&](ICurrentAppWithConsumables const& f) { return f.RequestProductPurchaseAsync(productId); });
    }
    inline auto CurrentApp::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties)
    {
        return impl::call_factory<CurrentApp, ICurrentAppWithConsumables>([&](ICurrentAppWithConsumables const& f) { return f.RequestProductPurchaseAsync(productId, offerId, displayProperties); });
    }
    inline auto CurrentApp::GetUnfulfilledConsumablesAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>(*)(ICurrentAppWithConsumables const&), CurrentApp, ICurrentAppWithConsumables>([](ICurrentAppWithConsumables const& f) { return f.GetUnfulfilledConsumablesAsync(); });
    }
    inline auto CurrentAppSimulator::LicenseInformation()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Store::LicenseInformation(*)(ICurrentAppSimulator const&), CurrentAppSimulator, ICurrentAppSimulator>([](ICurrentAppSimulator const& f) { return f.LicenseInformation(); });
    }
    inline auto CurrentAppSimulator::LinkUri()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Uri(*)(ICurrentAppSimulator const&), CurrentAppSimulator, ICurrentAppSimulator>([](ICurrentAppSimulator const& f) { return f.LinkUri(); });
    }
    inline auto CurrentAppSimulator::AppId()
    {
        return impl::call_factory_cast<winrt::guid(*)(ICurrentAppSimulator const&), CurrentAppSimulator, ICurrentAppSimulator>([](ICurrentAppSimulator const& f) { return f.AppId(); });
    }
    inline auto CurrentAppSimulator::RequestAppPurchaseAsync(bool includeReceipt)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulator>([&](ICurrentAppSimulator const& f) { return f.RequestAppPurchaseAsync(includeReceipt); });
    }
    inline auto CurrentAppSimulator::RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulator>([&](ICurrentAppSimulator const& f) { return f.RequestProductPurchaseAsync(productId, includeReceipt); });
    }
    inline auto CurrentAppSimulator::LoadListingInformationAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::ListingInformation>(*)(ICurrentAppSimulator const&), CurrentAppSimulator, ICurrentAppSimulator>([](ICurrentAppSimulator const& f) { return f.LoadListingInformationAsync(); });
    }
    inline auto CurrentAppSimulator::GetAppReceiptAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<hstring>(*)(ICurrentAppSimulator const&), CurrentAppSimulator, ICurrentAppSimulator>([](ICurrentAppSimulator const& f) { return f.GetAppReceiptAsync(); });
    }
    inline auto CurrentAppSimulator::GetProductReceiptAsync(param::hstring const& productId)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulator>([&](ICurrentAppSimulator const& f) { return f.GetProductReceiptAsync(productId); });
    }
    inline auto CurrentAppSimulator::ReloadSimulatorAsync(winrt::Windows::Storage::StorageFile const& simulatorSettingsFile)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulator>([&](ICurrentAppSimulator const& f) { return f.ReloadSimulatorAsync(simulatorSettingsFile); });
    }
    inline auto CurrentAppSimulator::LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulatorStaticsWithFiltering>([&](ICurrentAppSimulatorStaticsWithFiltering const& f) { return f.LoadListingInformationByProductIdsAsync(productIds); });
    }
    inline auto CurrentAppSimulator::LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulatorStaticsWithFiltering>([&](ICurrentAppSimulatorStaticsWithFiltering const& f) { return f.LoadListingInformationByKeywordsAsync(keywords); });
    }
    inline auto CurrentAppSimulator::GetAppPurchaseCampaignIdAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<hstring>(*)(ICurrentAppSimulatorWithCampaignId const&), CurrentAppSimulator, ICurrentAppSimulatorWithCampaignId>([](ICurrentAppSimulatorWithCampaignId const& f) { return f.GetAppPurchaseCampaignIdAsync(); });
    }
    inline auto CurrentAppSimulator::ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulatorWithConsumables>([&](ICurrentAppSimulatorWithConsumables const& f) { return f.ReportConsumableFulfillmentAsync(productId, transactionId); });
    }
    inline auto CurrentAppSimulator::RequestProductPurchaseAsync(param::hstring const& productId)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulatorWithConsumables>([&](ICurrentAppSimulatorWithConsumables const& f) { return f.RequestProductPurchaseAsync(productId); });
    }
    inline auto CurrentAppSimulator::RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties)
    {
        return impl::call_factory<CurrentAppSimulator, ICurrentAppSimulatorWithConsumables>([&](ICurrentAppSimulatorWithConsumables const& f) { return f.RequestProductPurchaseAsync(productId, offerId, displayProperties); });
    }
    inline auto CurrentAppSimulator::GetUnfulfilledConsumablesAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable>>(*)(ICurrentAppSimulatorWithConsumables const&), CurrentAppSimulator, ICurrentAppSimulatorWithConsumables>([](ICurrentAppSimulatorWithConsumables const& f) { return f.GetUnfulfilledConsumablesAsync(); });
    }
    inline ProductPurchaseDisplayProperties::ProductPurchaseDisplayProperties() :
        ProductPurchaseDisplayProperties(impl::call_factory_cast<ProductPurchaseDisplayProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), ProductPurchaseDisplayProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ProductPurchaseDisplayProperties>(); }))
    {
    }
    inline ProductPurchaseDisplayProperties::ProductPurchaseDisplayProperties(param::hstring const& name) :
        ProductPurchaseDisplayProperties(impl::call_factory<ProductPurchaseDisplayProperties, IProductPurchaseDisplayPropertiesFactory>([&](IProductPurchaseDisplayPropertiesFactory const& f) { return f.CreateProductPurchaseDisplayProperties(name); }))
    {
    }
    template <typename L> LicenseChangedEventHandler::LicenseChangedEventHandler(L handler) :
        LicenseChangedEventHandler(impl::make_delegate<LicenseChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> LicenseChangedEventHandler::LicenseChangedEventHandler(F* handler) :
        LicenseChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> LicenseChangedEventHandler::LicenseChangedEventHandler(O* object, M method) :
        LicenseChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> LicenseChangedEventHandler::LicenseChangedEventHandler(com_ptr<O>&& object, M method) :
        LicenseChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> LicenseChangedEventHandler::LicenseChangedEventHandler(weak_ref<O>&& object, M method) :
        LicenseChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto LicenseChangedEventHandler::operator()() const
    {
        check_hresult((*(impl::abi_t<LicenseChangedEventHandler>**)this)->Invoke());
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentApp2Statics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorStaticsWithFiltering> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithCampaignId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppSimulatorWithConsumables> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppStaticsWithFiltering> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppWithCampaignId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ICurrentAppWithConsumables> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ILicenseInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IListingInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IListingInformation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListing2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListingWithConsumables> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayPropertiesFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IPurchaseResults> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::CurrentApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::CurrentAppSimulator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ListingInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ProductLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ProductListing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::PurchaseResults> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::UnfulfilledConsumable> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
