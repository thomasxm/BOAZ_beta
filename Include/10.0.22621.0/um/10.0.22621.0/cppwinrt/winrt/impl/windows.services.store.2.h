// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Store_2_H
#define WINRT_Windows_Services_Store_2_H
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Services.Store.1.h"
WINRT_EXPORT namespace winrt::Windows::Services::Store
{
    struct StorePackageUpdateStatus
    {
        hstring PackageFamilyName;
        uint64_t PackageDownloadSizeInBytes;
        uint64_t PackageBytesDownloaded;
        double PackageDownloadProgress;
        double TotalDownloadProgress;
        winrt::Windows::Services::Store::StorePackageUpdateState PackageUpdateState;
    };
    inline bool operator==(StorePackageUpdateStatus const& left, StorePackageUpdateStatus const& right) noexcept
    {
        return left.PackageFamilyName == right.PackageFamilyName && left.PackageDownloadSizeInBytes == right.PackageDownloadSizeInBytes && left.PackageBytesDownloaded == right.PackageBytesDownloaded && left.PackageDownloadProgress == right.PackageDownloadProgress && left.TotalDownloadProgress == right.TotalDownloadProgress && left.PackageUpdateState == right.PackageUpdateState;
    }
    inline bool operator!=(StorePackageUpdateStatus const& left, StorePackageUpdateStatus const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) StoreAcquireLicenseResult : winrt::Windows::Services::Store::IStoreAcquireLicenseResult
    {
        StoreAcquireLicenseResult(std::nullptr_t) noexcept {}
        StoreAcquireLicenseResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreAcquireLicenseResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreAppLicense : winrt::Windows::Services::Store::IStoreAppLicense,
        impl::require<StoreAppLicense, winrt::Windows::Services::Store::IStoreAppLicense2>
    {
        StoreAppLicense(std::nullptr_t) noexcept {}
        StoreAppLicense(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreAppLicense(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreAvailability : winrt::Windows::Services::Store::IStoreAvailability
    {
        StoreAvailability(std::nullptr_t) noexcept {}
        StoreAvailability(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreAvailability(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreCanAcquireLicenseResult : winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult
    {
        StoreCanAcquireLicenseResult(std::nullptr_t) noexcept {}
        StoreCanAcquireLicenseResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreCollectionData : winrt::Windows::Services::Store::IStoreCollectionData
    {
        StoreCollectionData(std::nullptr_t) noexcept {}
        StoreCollectionData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreCollectionData(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreConsumableResult : winrt::Windows::Services::Store::IStoreConsumableResult
    {
        StoreConsumableResult(std::nullptr_t) noexcept {}
        StoreConsumableResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreConsumableResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreContext : winrt::Windows::Services::Store::IStoreContext,
        impl::require<StoreContext, winrt::Windows::Services::Store::IStoreContext2, winrt::Windows::Services::Store::IStoreContext3, winrt::Windows::Services::Store::IStoreContext4, winrt::Windows::Services::Store::IStoreContext5>
    {
        StoreContext(std::nullptr_t) noexcept {}
        StoreContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreContext(ptr, take_ownership_from_abi) {}
        using winrt::Windows::Services::Store::IStoreContext::GetStoreProductsAsync;
        using impl::consume_t<StoreContext, winrt::Windows::Services::Store::IStoreContext3>::GetStoreProductsAsync;
        using winrt::Windows::Services::Store::IStoreContext::RequestDownloadAndInstallStorePackagesAsync;
        using impl::consume_t<StoreContext, winrt::Windows::Services::Store::IStoreContext3>::RequestDownloadAndInstallStorePackagesAsync;
        static auto GetDefault();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) StoreImage : winrt::Windows::Services::Store::IStoreImage
    {
        StoreImage(std::nullptr_t) noexcept {}
        StoreImage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreImage(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreLicense : winrt::Windows::Services::Store::IStoreLicense
    {
        StoreLicense(std::nullptr_t) noexcept {}
        StoreLicense(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreLicense(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorePackageInstallOptions : winrt::Windows::Services::Store::IStorePackageInstallOptions
    {
        StorePackageInstallOptions(std::nullptr_t) noexcept {}
        StorePackageInstallOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePackageInstallOptions(ptr, take_ownership_from_abi) {}
        StorePackageInstallOptions();
    };
    struct __declspec(empty_bases) StorePackageLicense : winrt::Windows::Services::Store::IStorePackageLicense
    {
        StorePackageLicense(std::nullptr_t) noexcept {}
        StorePackageLicense(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePackageLicense(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorePackageUpdate : winrt::Windows::Services::Store::IStorePackageUpdate
    {
        StorePackageUpdate(std::nullptr_t) noexcept {}
        StorePackageUpdate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePackageUpdate(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorePackageUpdateResult : winrt::Windows::Services::Store::IStorePackageUpdateResult,
        impl::require<StorePackageUpdateResult, winrt::Windows::Services::Store::IStorePackageUpdateResult2>
    {
        StorePackageUpdateResult(std::nullptr_t) noexcept {}
        StorePackageUpdateResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePackageUpdateResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorePrice : winrt::Windows::Services::Store::IStorePrice,
        impl::require<StorePrice, winrt::Windows::Services::Store::IStorePrice2>
    {
        StorePrice(std::nullptr_t) noexcept {}
        StorePrice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePrice(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreProduct : winrt::Windows::Services::Store::IStoreProduct
    {
        StoreProduct(std::nullptr_t) noexcept {}
        StoreProduct(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreProduct(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreProductOptions : winrt::Windows::Services::Store::IStoreProductOptions
    {
        StoreProductOptions(std::nullptr_t) noexcept {}
        StoreProductOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreProductOptions(ptr, take_ownership_from_abi) {}
        StoreProductOptions();
    };
    struct __declspec(empty_bases) StoreProductPagedQueryResult : winrt::Windows::Services::Store::IStoreProductPagedQueryResult
    {
        StoreProductPagedQueryResult(std::nullptr_t) noexcept {}
        StoreProductPagedQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreProductPagedQueryResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreProductQueryResult : winrt::Windows::Services::Store::IStoreProductQueryResult
    {
        StoreProductQueryResult(std::nullptr_t) noexcept {}
        StoreProductQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreProductQueryResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreProductResult : winrt::Windows::Services::Store::IStoreProductResult
    {
        StoreProductResult(std::nullptr_t) noexcept {}
        StoreProductResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreProductResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StorePurchaseProperties : winrt::Windows::Services::Store::IStorePurchaseProperties
    {
        StorePurchaseProperties(std::nullptr_t) noexcept {}
        StorePurchaseProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePurchaseProperties(ptr, take_ownership_from_abi) {}
        StorePurchaseProperties();
        explicit StorePurchaseProperties(param::hstring const& name);
    };
    struct __declspec(empty_bases) StorePurchaseResult : winrt::Windows::Services::Store::IStorePurchaseResult
    {
        StorePurchaseResult(std::nullptr_t) noexcept {}
        StorePurchaseResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStorePurchaseResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreQueueItem : winrt::Windows::Services::Store::IStoreQueueItem,
        impl::require<StoreQueueItem, winrt::Windows::Services::Store::IStoreQueueItem2>
    {
        StoreQueueItem(std::nullptr_t) noexcept {}
        StoreQueueItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreQueueItem(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreQueueItemCompletedEventArgs : winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs
    {
        StoreQueueItemCompletedEventArgs(std::nullptr_t) noexcept {}
        StoreQueueItemCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreQueueItemStatus : winrt::Windows::Services::Store::IStoreQueueItemStatus
    {
        StoreQueueItemStatus(std::nullptr_t) noexcept {}
        StoreQueueItemStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreQueueItemStatus(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreRateAndReviewResult : winrt::Windows::Services::Store::IStoreRateAndReviewResult
    {
        StoreRateAndReviewResult(std::nullptr_t) noexcept {}
        StoreRateAndReviewResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreRateAndReviewResult(ptr, take_ownership_from_abi) {}
    };
    struct StoreRequestHelper
    {
        StoreRequestHelper() = delete;
        static auto SendRequestAsync(winrt::Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson);
    };
    struct __declspec(empty_bases) StoreSendRequestResult : winrt::Windows::Services::Store::IStoreSendRequestResult,
        impl::require<StoreSendRequestResult, winrt::Windows::Services::Store::IStoreSendRequestResult2>
    {
        StoreSendRequestResult(std::nullptr_t) noexcept {}
        StoreSendRequestResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreSendRequestResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreSku : winrt::Windows::Services::Store::IStoreSku
    {
        StoreSku(std::nullptr_t) noexcept {}
        StoreSku(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreSku(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreSubscriptionInfo : winrt::Windows::Services::Store::IStoreSubscriptionInfo
    {
        StoreSubscriptionInfo(std::nullptr_t) noexcept {}
        StoreSubscriptionInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreSubscriptionInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreUninstallStorePackageResult : winrt::Windows::Services::Store::IStoreUninstallStorePackageResult
    {
        StoreUninstallStorePackageResult(std::nullptr_t) noexcept {}
        StoreUninstallStorePackageResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreUninstallStorePackageResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StoreVideo : winrt::Windows::Services::Store::IStoreVideo
    {
        StoreVideo(std::nullptr_t) noexcept {}
        StoreVideo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Store::IStoreVideo(ptr, take_ownership_from_abi) {}
    };
}
#endif
