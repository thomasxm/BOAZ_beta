// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_Preview_H
#define WINRT_Windows_ApplicationModel_Store_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Store.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Core.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode) consume_Windows_ApplicationModel_Store_Preview_IDeliveryOptimizationSettings<D>::DownloadMode() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings)->get_DownloadMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource) consume_Windows_ApplicationModel_Store_Preview_IDeliveryOptimizationSettings<D>::DownloadModeSource() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings)->get_DownloadModeSource(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings) consume_Windows_ApplicationModel_Store_Preview_IDeliveryOptimizationSettingsStatics<D>::GetCurrentSettings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics)->GetCurrentSettings(&result));
        return winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::SetSystemConfiguration(param::hstring const& catalogHardwareManufacturerId, param::hstring const& catalogStoreContentModifierId, winrt::Windows::Foundation::DateTime const& systemConfigurationExpiration, param::hstring const& catalogHardwareDescriptor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->SetSystemConfiguration(*(void**)(&catalogHardwareManufacturerId), *(void**)(&catalogStoreContentModifierId), impl::bind_in(systemConfigurationExpiration), *(void**)(&catalogHardwareDescriptor)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::SetMobileOperatorConfiguration(param::hstring const& mobileOperatorId, uint32_t appDownloadLimitInMegabytes, uint32_t updateDownloadLimitInMegabytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->SetMobileOperatorConfiguration(*(void**)(&mobileOperatorId), appDownloadLimitInMegabytes, updateDownloadLimitInMegabytes));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::SetStoreWebAccountId(param::hstring const& webAccountId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->SetStoreWebAccountId(*(void**)(&webAccountId)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::IsStoreWebAccountId(param::hstring const& webAccountId) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->IsStoreWebAccountId(*(void**)(&webAccountId), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::HardwareManufacturerInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->get_HardwareManufacturerInfo(&value));
        return winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StoreSystemFeature>>) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics<D>::FilterUnsupportedSystemFeaturesAsync(param::async_iterable<winrt::Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const& systemFeatures) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics)->FilterUnsupportedSystemFeaturesAsync(*(void**)(&systemFeatures), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StoreSystemFeature>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics2<D>::PurchasePromptingPolicy() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2)->get_PurchasePromptingPolicy(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics2<D>::PurchasePromptingPolicy(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2)->put_PurchasePromptingPolicy(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::HasStoreWebAccount() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->HasStoreWebAccount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::HasStoreWebAccountForUser(winrt::Windows::System::User const& user) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->HasStoreWebAccountForUser(*(void**)(&user), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::GetStoreLogDataAsync(winrt::Windows::ApplicationModel::Store::Preview::StoreLogOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->GetStoreLogDataAsync(static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::SetStoreWebAccountIdForUser(winrt::Windows::System::User const& user, param::hstring const& webAccountId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->SetStoreWebAccountIdForUser(*(void**)(&user), *(void**)(&webAccountId)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::IsStoreWebAccountIdForUser(winrt::Windows::System::User const& user, param::hstring const& webAccountId) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->IsStoreWebAccountIdForUser(*(void**)(&user), *(void**)(&webAccountId), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::GetPurchasePromptingPolicyForUser(winrt::Windows::System::User const& user) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->GetPurchasePromptingPolicyForUser(*(void**)(&user), &value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics3<D>::SetPurchasePromptingPolicyForUser(winrt::Windows::System::User const& user, winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3)->SetPurchasePromptingPolicyForUser(*(void**)(&user), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetStoreWebAccountId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetStoreWebAccountId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetStoreWebAccountIdForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetStoreWebAccountIdForUser(*(void**)(&user), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::SetEnterpriseStoreWebAccountId(param::hstring const& webAccountId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->SetEnterpriseStoreWebAccountId(*(void**)(&webAccountId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::SetEnterpriseStoreWebAccountIdForUser(winrt::Windows::System::User const& user, param::hstring const& webAccountId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->SetEnterpriseStoreWebAccountIdForUser(*(void**)(&user), *(void**)(&webAccountId)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetEnterpriseStoreWebAccountId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetEnterpriseStoreWebAccountId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::GetEnterpriseStoreWebAccountIdForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->GetEnterpriseStoreWebAccountIdForUser(*(void**)(&user), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::ShouldRestrictToEnterpriseStoreOnly() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->ShouldRestrictToEnterpriseStoreOnly(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics4<D>::ShouldRestrictToEnterpriseStoreOnlyForUser(winrt::Windows::System::User const& user) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4)->ShouldRestrictToEnterpriseStoreOnlyForUser(*(void**)(&user), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::IsPinToDesktopSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->IsPinToDesktopSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::IsPinToTaskbarSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->IsPinToTaskbarSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::IsPinToStartSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->IsPinToStartSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::PinToDesktop(param::hstring const& appPackageFamilyName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->PinToDesktop(*(void**)(&appPackageFamilyName)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Store_Preview_IStoreConfigurationStatics5<D>::PinToDesktopForUser(winrt::Windows::System::User const& user, param::hstring const& appPackageFamilyName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5)->PinToDesktopForUser(*(void**)(&user), *(void**)(&appPackageFamilyName)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::HardwareManufacturerId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_HardwareManufacturerId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::StoreContentModifierId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_StoreContentModifierId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::ModelName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_ModelName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStoreHardwareManufacturerInfo<D>::ManufacturerName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo)->get_ManufacturerName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults>) consume_Windows_ApplicationModel_Store_Preview_IStorePreview<D>::RequestProductPurchaseByProductIdAndSkuIdAsync(param::hstring const& productId, param::hstring const& skuId) const
    {
        void* requestPurchaseBySkuIdOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreview)->RequestProductPurchaseByProductIdAndSkuIdAsync(*(void**)(&productId), *(void**)(&skuId), &requestPurchaseBySkuIdOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults>{ requestPurchaseBySkuIdOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>>) consume_Windows_ApplicationModel_Store_Preview_IStorePreview<D>::LoadAddOnProductInfosAsync() const
    {
        void* loadAddOnProductInfosOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreview)->LoadAddOnProductInfosAsync(&loadAddOnProductInfosOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>>{ loadAddOnProductInfosOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::ProductType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_ProductType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo>) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewProductInfo<D>::SkuInfoList() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo)->get_SkuInfoList(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewPurchaseResults<D>::ProductPurchaseStatus() const
    {
        winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults)->get_ProductPurchaseStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::ProductId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_ProductId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::SkuId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_SkuId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::SkuType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_SkuType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::CustomDeveloperData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_CustomDeveloperData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::CurrencyCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_CurrencyCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::FormattedListPrice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_FormattedListPrice(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Store_Preview_IStorePreviewSkuInfo<D>::ExtendedData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo)->get_ExtendedData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>) consume_Windows_ApplicationModel_Store_Preview_IWebAuthenticationCoreManagerHelper<D>::RequestTokenWithUIElementHostingAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::UI::Xaml::UIElement const& uiElement) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper)->RequestTokenWithUIElementHostingAsync(*(void**)(&request), *(void**)(&uiElement), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>) consume_Windows_ApplicationModel_Store_Preview_IWebAuthenticationCoreManagerHelper<D>::RequestTokenWithUIElementHostingAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::UI::Xaml::UIElement const& uiElement) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper)->RequestTokenWithUIElementHostingAndWebAccountAsync(*(void**)(&request), *(void**)(&webAccount), *(void**)(&uiElement), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>{ asyncInfo, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings>
    {
        int32_t __stdcall get_DownloadMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadMode>(this->shim().DownloadMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DownloadModeSource(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationDownloadModeSource>(this->shim().DownloadModeSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics>
    {
        int32_t __stdcall GetCurrentSettings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics>
    {
        int32_t __stdcall SetSystemConfiguration(void* catalogHardwareManufacturerId, void* catalogStoreContentModifierId, int64_t systemConfigurationExpiration, void* catalogHardwareDescriptor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSystemConfiguration(*reinterpret_cast<hstring const*>(&catalogHardwareManufacturerId), *reinterpret_cast<hstring const*>(&catalogStoreContentModifierId), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&systemConfigurationExpiration), *reinterpret_cast<hstring const*>(&catalogHardwareDescriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetMobileOperatorConfiguration(void* mobileOperatorId, uint32_t appDownloadLimitInMegabytes, uint32_t updateDownloadLimitInMegabytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetMobileOperatorConfiguration(*reinterpret_cast<hstring const*>(&mobileOperatorId), appDownloadLimitInMegabytes, updateDownloadLimitInMegabytes);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStoreWebAccountId(void* webAccountId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStoreWebAccountId(*reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsStoreWebAccountId(void* webAccountId, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStoreWebAccountId(*reinterpret_cast<hstring const*>(&webAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardwareManufacturerInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo>(this->shim().HardwareManufacturerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FilterUnsupportedSystemFeaturesAsync(void* systemFeatures, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StoreSystemFeature>>>(this->shim().FilterUnsupportedSystemFeaturesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const*>(&systemFeatures)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2>
    {
        int32_t __stdcall get_PurchasePromptingPolicy(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().PurchasePromptingPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PurchasePromptingPolicy(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PurchasePromptingPolicy(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3>
    {
        int32_t __stdcall HasStoreWebAccount(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasStoreWebAccount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HasStoreWebAccountForUser(void* user, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasStoreWebAccountForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStoreLogDataAsync(uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>>(this->shim().GetStoreLogDataAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::Preview::StoreLogOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStoreWebAccountIdForUser(void* user, void* webAccountId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStoreWebAccountIdForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsStoreWebAccountIdForUser(void* user, void* webAccountId, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStoreWebAccountIdForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPurchasePromptingPolicyForUser(void* user, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().GetPurchasePromptingPolicyForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPurchasePromptingPolicyForUser(void* user, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPurchasePromptingPolicyForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4>
    {
        int32_t __stdcall GetStoreWebAccountId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetStoreWebAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStoreWebAccountIdForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetStoreWebAccountIdForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEnterpriseStoreWebAccountId(void* webAccountId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEnterpriseStoreWebAccountId(*reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEnterpriseStoreWebAccountIdForUser(void* user, void* webAccountId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEnterpriseStoreWebAccountIdForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEnterpriseStoreWebAccountId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetEnterpriseStoreWebAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEnterpriseStoreWebAccountIdForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetEnterpriseStoreWebAccountIdForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShouldRestrictToEnterpriseStoreOnly(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldRestrictToEnterpriseStoreOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShouldRestrictToEnterpriseStoreOnlyForUser(void* user, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldRestrictToEnterpriseStoreOnlyForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5>
    {
        int32_t __stdcall IsPinToDesktopSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPinToDesktopSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPinToTaskbarSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPinToTaskbarSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPinToStartSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPinToStartSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PinToDesktop(void* appPackageFamilyName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToDesktop(*reinterpret_cast<hstring const*>(&appPackageFamilyName));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PinToDesktopForUser(void* user, void* appPackageFamilyName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PinToDesktopForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&appPackageFamilyName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo>
    {
        int32_t __stdcall get_HardwareManufacturerId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HardwareManufacturerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StoreContentModifierId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StoreContentModifierId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManufacturerName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ManufacturerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreview> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreview>
    {
        int32_t __stdcall RequestProductPurchaseByProductIdAndSkuIdAsync(void* productId, void* skuId, void** requestPurchaseBySkuIdOperation) noexcept final try
        {
            clear_abi(requestPurchaseBySkuIdOperation);
            typename D::abi_guard guard(this->shim());
            *requestPurchaseBySkuIdOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults>>(this->shim().RequestProductPurchaseByProductIdAndSkuIdAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadAddOnProductInfosAsync(void** loadAddOnProductInfosOperation) noexcept final try
        {
            clear_abi(loadAddOnProductInfosOperation);
            typename D::abi_guard guard(this->shim());
            *loadAddOnProductInfosOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>>>(this->shim().LoadAddOnProductInfosAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo>
    {
        int32_t __stdcall get_ProductId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProductType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductType());
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
        int32_t __stdcall get_SkuInfoList(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo>>(this->shim().SkuInfoList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults>
    {
        int32_t __stdcall get_ProductPurchaseStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductPurchaseStatus>(this->shim().ProductPurchaseStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo>
    {
        int32_t __stdcall get_ProductId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SkuId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SkuId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SkuType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SkuType());
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
        int32_t __stdcall get_CustomDeveloperData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CustomDeveloperData());
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
        int32_t __stdcall get_FormattedListPrice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormattedListPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper> : produce_base<D, winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper>
    {
        int32_t __stdcall RequestTokenWithUIElementHostingAsync(void* request, void* uiElement, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenWithUIElementHostingAsync(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&uiElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestTokenWithUIElementHostingAndWebAccountAsync(void* request, void* webAccount, void* uiElement, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenWithUIElementHostingAsync(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&uiElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::Preview
{
    constexpr auto operator|(StoreLogOptions const left, StoreLogOptions const right) noexcept
    {
        return static_cast<StoreLogOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(StoreLogOptions& left, StoreLogOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(StoreLogOptions const left, StoreLogOptions const right) noexcept
    {
        return static_cast<StoreLogOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(StoreLogOptions& left, StoreLogOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(StoreLogOptions const value) noexcept
    {
        return static_cast<StoreLogOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(StoreLogOptions const left, StoreLogOptions const right) noexcept
    {
        return static_cast<StoreLogOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(StoreLogOptions& left, StoreLogOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto DeliveryOptimizationSettings::GetCurrentSettings()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings(*)(IDeliveryOptimizationSettingsStatics const&), DeliveryOptimizationSettings, IDeliveryOptimizationSettingsStatics>([](IDeliveryOptimizationSettingsStatics const& f) { return f.GetCurrentSettings(); });
    }
    inline auto StoreConfiguration::SetSystemConfiguration(param::hstring const& catalogHardwareManufacturerId, param::hstring const& catalogStoreContentModifierId, winrt::Windows::Foundation::DateTime const& systemConfigurationExpiration, param::hstring const& catalogHardwareDescriptor)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics>([&](IStoreConfigurationStatics const& f) { return f.SetSystemConfiguration(catalogHardwareManufacturerId, catalogStoreContentModifierId, systemConfigurationExpiration, catalogHardwareDescriptor); });
    }
    inline auto StoreConfiguration::SetMobileOperatorConfiguration(param::hstring const& mobileOperatorId, uint32_t appDownloadLimitInMegabytes, uint32_t updateDownloadLimitInMegabytes)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics>([&](IStoreConfigurationStatics const& f) { return f.SetMobileOperatorConfiguration(mobileOperatorId, appDownloadLimitInMegabytes, updateDownloadLimitInMegabytes); });
    }
    inline auto StoreConfiguration::SetStoreWebAccountId(param::hstring const& webAccountId)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics>([&](IStoreConfigurationStatics const& f) { return f.SetStoreWebAccountId(webAccountId); });
    }
    inline auto StoreConfiguration::IsStoreWebAccountId(param::hstring const& webAccountId)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics>([&](IStoreConfigurationStatics const& f) { return f.IsStoreWebAccountId(webAccountId); });
    }
    inline auto StoreConfiguration::HardwareManufacturerInfo()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo(*)(IStoreConfigurationStatics const&), StoreConfiguration, IStoreConfigurationStatics>([](IStoreConfigurationStatics const& f) { return f.HardwareManufacturerInfo(); });
    }
    inline auto StoreConfiguration::FilterUnsupportedSystemFeaturesAsync(param::async_iterable<winrt::Windows::ApplicationModel::Store::Preview::StoreSystemFeature> const& systemFeatures)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics>([&](IStoreConfigurationStatics const& f) { return f.FilterUnsupportedSystemFeaturesAsync(systemFeatures); });
    }
    inline auto StoreConfiguration::PurchasePromptingPolicy()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IReference<uint32_t>(*)(IStoreConfigurationStatics2 const&), StoreConfiguration, IStoreConfigurationStatics2>([](IStoreConfigurationStatics2 const& f) { return f.PurchasePromptingPolicy(); });
    }
    inline auto StoreConfiguration::PurchasePromptingPolicy(winrt::Windows::Foundation::IReference<uint32_t> const& value)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics2>([&](IStoreConfigurationStatics2 const& f) { return f.PurchasePromptingPolicy(value); });
    }
    inline auto StoreConfiguration::HasStoreWebAccount()
    {
        return impl::call_factory_cast<bool(*)(IStoreConfigurationStatics3 const&), StoreConfiguration, IStoreConfigurationStatics3>([](IStoreConfigurationStatics3 const& f) { return f.HasStoreWebAccount(); });
    }
    inline auto StoreConfiguration::HasStoreWebAccountForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics3>([&](IStoreConfigurationStatics3 const& f) { return f.HasStoreWebAccountForUser(user); });
    }
    inline auto StoreConfiguration::GetStoreLogDataAsync(winrt::Windows::ApplicationModel::Store::Preview::StoreLogOptions const& options)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics3>([&](IStoreConfigurationStatics3 const& f) { return f.GetStoreLogDataAsync(options); });
    }
    inline auto StoreConfiguration::SetStoreWebAccountIdForUser(winrt::Windows::System::User const& user, param::hstring const& webAccountId)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics3>([&](IStoreConfigurationStatics3 const& f) { return f.SetStoreWebAccountIdForUser(user, webAccountId); });
    }
    inline auto StoreConfiguration::IsStoreWebAccountIdForUser(winrt::Windows::System::User const& user, param::hstring const& webAccountId)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics3>([&](IStoreConfigurationStatics3 const& f) { return f.IsStoreWebAccountIdForUser(user, webAccountId); });
    }
    inline auto StoreConfiguration::GetPurchasePromptingPolicyForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics3>([&](IStoreConfigurationStatics3 const& f) { return f.GetPurchasePromptingPolicyForUser(user); });
    }
    inline auto StoreConfiguration::SetPurchasePromptingPolicyForUser(winrt::Windows::System::User const& user, winrt::Windows::Foundation::IReference<uint32_t> const& value)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics3>([&](IStoreConfigurationStatics3 const& f) { return f.SetPurchasePromptingPolicyForUser(user, value); });
    }
    inline auto StoreConfiguration::GetStoreWebAccountId()
    {
        return impl::call_factory_cast<hstring(*)(IStoreConfigurationStatics4 const&), StoreConfiguration, IStoreConfigurationStatics4>([](IStoreConfigurationStatics4 const& f) { return f.GetStoreWebAccountId(); });
    }
    inline auto StoreConfiguration::GetStoreWebAccountIdForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics4>([&](IStoreConfigurationStatics4 const& f) { return f.GetStoreWebAccountIdForUser(user); });
    }
    inline auto StoreConfiguration::SetEnterpriseStoreWebAccountId(param::hstring const& webAccountId)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics4>([&](IStoreConfigurationStatics4 const& f) { return f.SetEnterpriseStoreWebAccountId(webAccountId); });
    }
    inline auto StoreConfiguration::SetEnterpriseStoreWebAccountIdForUser(winrt::Windows::System::User const& user, param::hstring const& webAccountId)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics4>([&](IStoreConfigurationStatics4 const& f) { return f.SetEnterpriseStoreWebAccountIdForUser(user, webAccountId); });
    }
    inline auto StoreConfiguration::GetEnterpriseStoreWebAccountId()
    {
        return impl::call_factory_cast<hstring(*)(IStoreConfigurationStatics4 const&), StoreConfiguration, IStoreConfigurationStatics4>([](IStoreConfigurationStatics4 const& f) { return f.GetEnterpriseStoreWebAccountId(); });
    }
    inline auto StoreConfiguration::GetEnterpriseStoreWebAccountIdForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics4>([&](IStoreConfigurationStatics4 const& f) { return f.GetEnterpriseStoreWebAccountIdForUser(user); });
    }
    inline auto StoreConfiguration::ShouldRestrictToEnterpriseStoreOnly()
    {
        return impl::call_factory_cast<bool(*)(IStoreConfigurationStatics4 const&), StoreConfiguration, IStoreConfigurationStatics4>([](IStoreConfigurationStatics4 const& f) { return f.ShouldRestrictToEnterpriseStoreOnly(); });
    }
    inline auto StoreConfiguration::ShouldRestrictToEnterpriseStoreOnlyForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<StoreConfiguration, IStoreConfigurationStatics4>([&](IStoreConfigurationStatics4 const& f) { return f.ShouldRestrictToEnterpriseStoreOnlyForUser(user); });
    }
    inline auto StoreConfiguration::IsPinToDesktopSupported()
    {
        return impl::call_factory_cast<bool(*)(IStoreConfigurationStatics5 const&), StoreConfiguration, IStoreConfigurationStatics5>([](IStoreConfigurationStatics5 const& f) { return f.IsPinToDesktopSupported(); });
    }
    inline auto StoreConfiguration::IsPinToTaskbarSupported()
    {
        return impl::call_factory_cast<bool(*)(IStoreConfigurationStatics5 const&), StoreConfiguration, IStoreConfigurationStatics5>([](IStoreConfigurationStatics5 const& f) { return f.IsPinToTaskbarSupported(); });
    }
    inline auto StoreConfiguration::IsPinToStartSupported()
    {
        return impl::call_factory_cast<bool(*)(IStoreConfigurationStatics5 const&), StoreConfiguration, IStoreConfigurationStatics5>([](IStoreConfigurationStatics5 const& f) { return f.IsPinToStartSupported(); });
    }
    inline auto StoreConfiguration::PinToDesktop(param::hstring const& appPackageFamilyName)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics5>([&](IStoreConfigurationStatics5 const& f) { return f.PinToDesktop(appPackageFamilyName); });
    }
    inline auto StoreConfiguration::PinToDesktopForUser(winrt::Windows::System::User const& user, param::hstring const& appPackageFamilyName)
    {
        impl::call_factory<StoreConfiguration, IStoreConfigurationStatics5>([&](IStoreConfigurationStatics5 const& f) { return f.PinToDesktopForUser(user, appPackageFamilyName); });
    }
    inline auto StorePreview::RequestProductPurchaseByProductIdAndSkuIdAsync(param::hstring const& productId, param::hstring const& skuId)
    {
        return impl::call_factory<StorePreview, IStorePreview>([&](IStorePreview const& f) { return f.RequestProductPurchaseByProductIdAndSkuIdAsync(productId, skuId); });
    }
    inline auto StorePreview::LoadAddOnProductInfosAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo>>(*)(IStorePreview const&), StorePreview, IStorePreview>([](IStorePreview const& f) { return f.LoadAddOnProductInfosAsync(); });
    }
    inline auto WebAuthenticationCoreManagerHelper::RequestTokenWithUIElementHostingAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::UI::Xaml::UIElement const& uiElement)
    {
        return impl::call_factory<WebAuthenticationCoreManagerHelper, IWebAuthenticationCoreManagerHelper>([&](IWebAuthenticationCoreManagerHelper const& f) { return f.RequestTokenWithUIElementHostingAsync(request, uiElement); });
    }
    inline auto WebAuthenticationCoreManagerHelper::RequestTokenWithUIElementHostingAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::UI::Xaml::UIElement const& uiElement)
    {
        return impl::call_factory<WebAuthenticationCoreManagerHelper, IWebAuthenticationCoreManagerHelper>([&](IWebAuthenticationCoreManagerHelper const& f) { return f.RequestTokenWithUIElementHostingAsync(request, webAccount, uiElement); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IDeliveryOptimizationSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreConfigurationStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStoreHardwareManufacturerInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewProductInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewPurchaseResults> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IStorePreviewSkuInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::IWebAuthenticationCoreManagerHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::DeliveryOptimizationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StoreConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StoreHardwareManufacturerInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewProductInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewPurchaseResults> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::StorePreviewSkuInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::WebAuthenticationCoreManagerHelper> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
