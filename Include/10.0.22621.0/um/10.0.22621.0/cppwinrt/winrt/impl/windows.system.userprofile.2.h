// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_UserProfile_2_H
#define WINRT_Windows_System_UserProfile_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.System.UserProfile.1.h"
WINRT_EXPORT namespace winrt::Windows::System::UserProfile
{
    struct AdvertisingManager
    {
        AdvertisingManager() = delete;
        [[nodiscard]] static auto AdvertisingId();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) AdvertisingManagerForUser : winrt::Windows::System::UserProfile::IAdvertisingManagerForUser
    {
        AdvertisingManagerForUser(std::nullptr_t) noexcept {}
        AdvertisingManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::UserProfile::IAdvertisingManagerForUser(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AssignedAccessSettings : winrt::Windows::System::UserProfile::IAssignedAccessSettings
    {
        AssignedAccessSettings(std::nullptr_t) noexcept {}
        AssignedAccessSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::UserProfile::IAssignedAccessSettings(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) DiagnosticsSettings : winrt::Windows::System::UserProfile::IDiagnosticsSettings
    {
        DiagnosticsSettings(std::nullptr_t) noexcept {}
        DiagnosticsSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::UserProfile::IDiagnosticsSettings(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) FirstSignInSettings : winrt::Windows::System::UserProfile::IFirstSignInSettings
    {
        FirstSignInSettings(std::nullptr_t) noexcept {}
        FirstSignInSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::UserProfile::IFirstSignInSettings(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
    };
    struct GlobalizationPreferences
    {
        GlobalizationPreferences() = delete;
        [[nodiscard]] static auto Calendars();
        [[nodiscard]] static auto Clocks();
        [[nodiscard]] static auto Currencies();
        [[nodiscard]] static auto Languages();
        [[nodiscard]] static auto HomeGeographicRegion();
        [[nodiscard]] static auto WeekStartsOn();
        static auto TrySetHomeGeographicRegion(param::hstring const& region);
        static auto TrySetLanguages(param::iterable<hstring> const& languageTags);
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) GlobalizationPreferencesForUser : winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser
    {
        GlobalizationPreferencesForUser(std::nullptr_t) noexcept {}
        GlobalizationPreferencesForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser(ptr, take_ownership_from_abi) {}
    };
    struct LockScreen
    {
        LockScreen() = delete;
        static auto RequestSetImageFeedAsync(winrt::Windows::Foundation::Uri const& syndicationFeedUri);
        static auto TryRemoveImageFeed();
        [[nodiscard]] static auto OriginalImageFile();
        static auto GetImageStream();
        static auto SetImageFileAsync(winrt::Windows::Storage::IStorageFile const& value);
        static auto SetImageStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& value);
    };
    struct UserInformation
    {
        UserInformation() = delete;
        [[nodiscard]] static auto AccountPictureChangeEnabled();
        [[nodiscard]] static auto NameAccessAllowed();
        static auto GetAccountPicture(winrt::Windows::System::UserProfile::AccountPictureKind const& kind);
        static auto SetAccountPictureAsync(winrt::Windows::Storage::IStorageFile const& image);
        static auto SetAccountPicturesAsync(winrt::Windows::Storage::IStorageFile const& smallImage, winrt::Windows::Storage::IStorageFile const& largeImage, winrt::Windows::Storage::IStorageFile const& video);
        static auto SetAccountPictureFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& image);
        static auto SetAccountPicturesFromStreamsAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& smallImage, winrt::Windows::Storage::Streams::IRandomAccessStream const& largeImage, winrt::Windows::Storage::Streams::IRandomAccessStream const& video);
        static auto AccountPictureChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& changeHandler);
        using AccountPictureChanged_revoker = impl::factory_event_revoker<winrt::Windows::System::UserProfile::IUserInformationStatics, &impl::abi_t<winrt::Windows::System::UserProfile::IUserInformationStatics>::remove_AccountPictureChanged>;
        [[nodiscard]] static AccountPictureChanged_revoker AccountPictureChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& changeHandler);
        static auto AccountPictureChanged(winrt::event_token const& token);
        static auto GetDisplayNameAsync();
        static auto GetFirstNameAsync();
        static auto GetLastNameAsync();
        static auto GetPrincipalNameAsync();
        static auto GetSessionInitiationProtocolUriAsync();
        static auto GetDomainNameAsync();
    };
    struct __declspec(empty_bases) UserProfilePersonalizationSettings : winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings
    {
        UserProfilePersonalizationSettings(std::nullptr_t) noexcept {}
        UserProfilePersonalizationSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Current();
        static auto IsSupported();
    };
}
#endif
