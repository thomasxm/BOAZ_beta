// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_2_H
#define WINRT_Windows_ApplicationModel_Store_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.ApplicationModel.Store.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store
{
    struct LicenseChangedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        LicenseChangedEventHandler(std::nullptr_t = nullptr) noexcept {}
        LicenseChangedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> LicenseChangedEventHandler(L lambda);
        template <typename F> LicenseChangedEventHandler(F* function);
        template <typename O, typename M> LicenseChangedEventHandler(O* object, M method);
        template <typename O, typename M> LicenseChangedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> LicenseChangedEventHandler(weak_ref<O>&& object, M method);
        auto operator()() const;
    };
    struct CurrentApp
    {
        CurrentApp() = delete;
        [[nodiscard]] static auto LicenseInformation();
        [[nodiscard]] static auto LinkUri();
        [[nodiscard]] static auto AppId();
        static auto RequestAppPurchaseAsync(bool includeReceipt);
        static auto RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt);
        static auto LoadListingInformationAsync();
        static auto GetAppReceiptAsync();
        static auto GetProductReceiptAsync(param::hstring const& productId);
        static auto GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId);
        static auto GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId);
        static auto LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds);
        static auto LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords);
        static auto ReportProductFulfillment(param::hstring const& productId);
        static auto GetAppPurchaseCampaignIdAsync();
        static auto ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId);
        static auto RequestProductPurchaseAsync(param::hstring const& productId);
        static auto RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties);
        static auto GetUnfulfilledConsumablesAsync();
    };
    struct CurrentAppSimulator
    {
        CurrentAppSimulator() = delete;
        [[nodiscard]] static auto LicenseInformation();
        [[nodiscard]] static auto LinkUri();
        [[nodiscard]] static auto AppId();
        static auto RequestAppPurchaseAsync(bool includeReceipt);
        static auto RequestProductPurchaseAsync(param::hstring const& productId, bool includeReceipt);
        static auto LoadListingInformationAsync();
        static auto GetAppReceiptAsync();
        static auto GetProductReceiptAsync(param::hstring const& productId);
        static auto ReloadSimulatorAsync(winrt::Windows::Storage::StorageFile const& simulatorSettingsFile);
        static auto LoadListingInformationByProductIdsAsync(param::async_iterable<hstring> const& productIds);
        static auto LoadListingInformationByKeywordsAsync(param::async_iterable<hstring> const& keywords);
        static auto GetAppPurchaseCampaignIdAsync();
        static auto ReportConsumableFulfillmentAsync(param::hstring const& productId, winrt::guid const& transactionId);
        static auto RequestProductPurchaseAsync(param::hstring const& productId);
        static auto RequestProductPurchaseAsync(param::hstring const& productId, param::hstring const& offerId, winrt::Windows::ApplicationModel::Store::ProductPurchaseDisplayProperties const& displayProperties);
        static auto GetUnfulfilledConsumablesAsync();
    };
    struct __declspec(empty_bases) LicenseInformation : winrt::Windows::ApplicationModel::Store::ILicenseInformation
    {
        LicenseInformation(std::nullptr_t) noexcept {}
        LicenseInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::ILicenseInformation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ListingInformation : winrt::Windows::ApplicationModel::Store::IListingInformation,
        impl::require<ListingInformation, winrt::Windows::ApplicationModel::Store::IListingInformation2>
    {
        ListingInformation(std::nullptr_t) noexcept {}
        ListingInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::IListingInformation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProductLicense : winrt::Windows::ApplicationModel::Store::IProductLicense,
        impl::require<ProductLicense, winrt::Windows::ApplicationModel::Store::IProductLicenseWithFulfillment>
    {
        ProductLicense(std::nullptr_t) noexcept {}
        ProductLicense(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::IProductLicense(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProductListing : winrt::Windows::ApplicationModel::Store::IProductListing,
        impl::require<ProductListing, winrt::Windows::ApplicationModel::Store::IProductListingWithMetadata, winrt::Windows::ApplicationModel::Store::IProductListing2>
    {
        ProductListing(std::nullptr_t) noexcept {}
        ProductListing(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::IProductListing(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProductPurchaseDisplayProperties : winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties
    {
        ProductPurchaseDisplayProperties(std::nullptr_t) noexcept {}
        ProductPurchaseDisplayProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::IProductPurchaseDisplayProperties(ptr, take_ownership_from_abi) {}
        ProductPurchaseDisplayProperties();
        explicit ProductPurchaseDisplayProperties(param::hstring const& name);
    };
    struct __declspec(empty_bases) PurchaseResults : winrt::Windows::ApplicationModel::Store::IPurchaseResults
    {
        PurchaseResults(std::nullptr_t) noexcept {}
        PurchaseResults(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::IPurchaseResults(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UnfulfilledConsumable : winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable
    {
        UnfulfilledConsumable(std::nullptr_t) noexcept {}
        UnfulfilledConsumable(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::IUnfulfilledConsumable(ptr, take_ownership_from_abi) {}
    };
}
#endif
