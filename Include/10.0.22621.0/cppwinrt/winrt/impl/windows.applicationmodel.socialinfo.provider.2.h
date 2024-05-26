// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_SocialInfo_Provider_2_H
#define WINRT_Windows_ApplicationModel_SocialInfo_Provider_2_H
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.1.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo::Provider
{
    struct __declspec(empty_bases) SocialDashboardItemUpdater : winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater
    {
        SocialDashboardItemUpdater(std::nullptr_t) noexcept {}
        SocialDashboardItemUpdater(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SocialFeedUpdater : winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater
    {
        SocialFeedUpdater(std::nullptr_t) noexcept {}
        SocialFeedUpdater(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater(ptr, take_ownership_from_abi) {}
    };
    struct SocialInfoProviderManager
    {
        SocialInfoProviderManager() = delete;
        static auto CreateSocialFeedUpdaterAsync(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind, winrt::Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const& mode, param::hstring const& ownerRemoteId);
        static auto CreateDashboardItemUpdaterAsync(param::hstring const& ownerRemoteId);
        static auto UpdateBadgeCountValue(param::hstring const& itemRemoteId, int32_t newCount);
        static auto ReportNewContentAvailable(param::hstring const& contactRemoteId, winrt::Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind);
        static auto ProvisionAsync();
        static auto DeprovisionAsync();
    };
}
#endif
