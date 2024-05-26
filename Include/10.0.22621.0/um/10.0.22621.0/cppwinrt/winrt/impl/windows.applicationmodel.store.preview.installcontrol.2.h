// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_Preview_InstallControl_2_H
#define WINRT_Windows_ApplicationModel_Store_Preview_InstallControl_2_H
#include "winrt/impl/Windows.ApplicationModel.Store.Preview.InstallControl.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::Preview::InstallControl
{
    struct __declspec(empty_bases) AppInstallItem : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem,
        impl::require<AppInstallItem, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5>
    {
        AppInstallItem(std::nullptr_t) noexcept {}
        AppInstallItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem(ptr, take_ownership_from_abi) {}
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem::Cancel;
        using impl::consume_t<AppInstallItem, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2>::Cancel;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem::Pause;
        using impl::consume_t<AppInstallItem, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2>::Pause;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem::Restart;
        using impl::consume_t<AppInstallItem, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2>::Restart;
    };
    struct __declspec(empty_bases) AppInstallManager : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager,
        impl::require<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7>
    {
        AppInstallManager(std::nullptr_t) noexcept {}
        AppInstallManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager(ptr, take_ownership_from_abi) {}
        AppInstallManager();
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::Cancel;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::Cancel;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::GetIsAppAllowedToInstallAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::GetIsAppAllowedToInstallAsync;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::Pause;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::Pause;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::Restart;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::Restart;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::SearchForAllUpdatesAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::SearchForAllUpdatesAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>::SearchForAllUpdatesAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3>::SearchForAllUpdatesForUserAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>::SearchForAllUpdatesForUserAsync;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::SearchForUpdatesAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::SearchForUpdatesAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>::SearchForUpdatesAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3>::SearchForUpdatesForUserAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>::SearchForUpdatesForUserAsync;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::StartAppInstallAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::StartAppInstallAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3>::StartProductInstallAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>::StartProductInstallAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3>::StartProductInstallForUserAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>::StartProductInstallForUserAsync;
        using winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager::UpdateAppByPackageFamilyNameAsync;
        using impl::consume_t<AppInstallManager, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>::UpdateAppByPackageFamilyNameAsync;
    };
    struct __declspec(empty_bases) AppInstallManagerItemEventArgs : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs
    {
        AppInstallManagerItemEventArgs(std::nullptr_t) noexcept {}
        AppInstallManagerItemEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppInstallOptions : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions,
        impl::require<AppInstallOptions, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2>
    {
        AppInstallOptions(std::nullptr_t) noexcept {}
        AppInstallOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions(ptr, take_ownership_from_abi) {}
        AppInstallOptions();
    };
    struct __declspec(empty_bases) AppInstallStatus : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus,
        impl::require<AppInstallStatus, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3>
    {
        AppInstallStatus(std::nullptr_t) noexcept {}
        AppInstallStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppUpdateOptions : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions,
        impl::require<AppUpdateOptions, winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2>
    {
        AppUpdateOptions(std::nullptr_t) noexcept {}
        AppUpdateOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions(ptr, take_ownership_from_abi) {}
        AppUpdateOptions();
    };
    struct __declspec(empty_bases) GetEntitlementResult : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult
    {
        GetEntitlementResult(std::nullptr_t) noexcept {}
        GetEntitlementResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult(ptr, take_ownership_from_abi) {}
    };
}
#endif
