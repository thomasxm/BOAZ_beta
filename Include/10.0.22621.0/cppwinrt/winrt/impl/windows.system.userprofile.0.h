// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_UserProfile_0_H
#define WINRT_Windows_System_UserProfile_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Globalization
{
    enum class DayOfWeek : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
    struct StorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IRandomAccessStream;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::System::UserProfile
{
    enum class AccountPictureKind : int32_t
    {
        SmallImage = 0,
        LargeImage = 1,
        Video = 2,
    };
    enum class SetAccountPictureResult : int32_t
    {
        Success = 0,
        ChangeDisabled = 1,
        LargeOrDynamicError = 2,
        VideoFrameSizeError = 3,
        FileSizeError = 4,
        Failure = 5,
    };
    enum class SetImageFeedResult : int32_t
    {
        Success = 0,
        ChangeDisabled = 1,
        UserCanceled = 2,
    };
    struct IAdvertisingManagerForUser;
    struct IAdvertisingManagerStatics;
    struct IAdvertisingManagerStatics2;
    struct IAssignedAccessSettings;
    struct IAssignedAccessSettingsStatics;
    struct IDiagnosticsSettings;
    struct IDiagnosticsSettingsStatics;
    struct IFirstSignInSettings;
    struct IFirstSignInSettingsStatics;
    struct IGlobalizationPreferencesForUser;
    struct IGlobalizationPreferencesStatics;
    struct IGlobalizationPreferencesStatics2;
    struct IGlobalizationPreferencesStatics3;
    struct ILockScreenImageFeedStatics;
    struct ILockScreenStatics;
    struct IUserInformationStatics;
    struct IUserProfilePersonalizationSettings;
    struct IUserProfilePersonalizationSettingsStatics;
    struct AdvertisingManager;
    struct AdvertisingManagerForUser;
    struct AssignedAccessSettings;
    struct DiagnosticsSettings;
    struct FirstSignInSettings;
    struct GlobalizationPreferences;
    struct GlobalizationPreferencesForUser;
    struct LockScreen;
    struct UserInformation;
    struct UserProfilePersonalizationSettings;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IAssignedAccessSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IDiagnosticsSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IFirstSignInSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::ILockScreenStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IUserInformationStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::UserProfile::AdvertisingManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::AdvertisingManagerForUser>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::AssignedAccessSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::DiagnosticsSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::FirstSignInSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::GlobalizationPreferences>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::GlobalizationPreferencesForUser>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::LockScreen>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::UserInformation>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::UserProfilePersonalizationSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::UserProfile::AccountPictureKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::System::UserProfile::SetAccountPictureResult>{ using type = enum_category; };
    template <> struct category<winrt::Windows::System::UserProfile::SetImageFeedResult>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::AdvertisingManager> = L"Windows.System.UserProfile.AdvertisingManager";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::AdvertisingManagerForUser> = L"Windows.System.UserProfile.AdvertisingManagerForUser";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::AssignedAccessSettings> = L"Windows.System.UserProfile.AssignedAccessSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::DiagnosticsSettings> = L"Windows.System.UserProfile.DiagnosticsSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::FirstSignInSettings> = L"Windows.System.UserProfile.FirstSignInSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::GlobalizationPreferences> = L"Windows.System.UserProfile.GlobalizationPreferences";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::GlobalizationPreferencesForUser> = L"Windows.System.UserProfile.GlobalizationPreferencesForUser";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::LockScreen> = L"Windows.System.UserProfile.LockScreen";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::UserInformation> = L"Windows.System.UserProfile.UserInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::UserProfilePersonalizationSettings> = L"Windows.System.UserProfile.UserProfilePersonalizationSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::AccountPictureKind> = L"Windows.System.UserProfile.AccountPictureKind";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::SetAccountPictureResult> = L"Windows.System.UserProfile.SetAccountPictureResult";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::SetImageFeedResult> = L"Windows.System.UserProfile.SetImageFeedResult";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser> = L"Windows.System.UserProfile.IAdvertisingManagerForUser";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics> = L"Windows.System.UserProfile.IAdvertisingManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2> = L"Windows.System.UserProfile.IAdvertisingManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IAssignedAccessSettings> = L"Windows.System.UserProfile.IAssignedAccessSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics> = L"Windows.System.UserProfile.IAssignedAccessSettingsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IDiagnosticsSettings> = L"Windows.System.UserProfile.IDiagnosticsSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics> = L"Windows.System.UserProfile.IDiagnosticsSettingsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IFirstSignInSettings> = L"Windows.System.UserProfile.IFirstSignInSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics> = L"Windows.System.UserProfile.IFirstSignInSettingsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser> = L"Windows.System.UserProfile.IGlobalizationPreferencesForUser";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics> = L"Windows.System.UserProfile.IGlobalizationPreferencesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2> = L"Windows.System.UserProfile.IGlobalizationPreferencesStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3> = L"Windows.System.UserProfile.IGlobalizationPreferencesStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics> = L"Windows.System.UserProfile.ILockScreenImageFeedStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::ILockScreenStatics> = L"Windows.System.UserProfile.ILockScreenStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IUserInformationStatics> = L"Windows.System.UserProfile.IUserInformationStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings> = L"Windows.System.UserProfile.IUserProfilePersonalizationSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics> = L"Windows.System.UserProfile.IUserProfilePersonalizationSettingsStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser>{ 0x928BF3D0,0xCF7C,0x4AB0,{ 0xA7,0xDC,0x6D,0xC5,0xBC,0xD4,0x42,0x52 } }; // 928BF3D0-CF7C-4AB0-A7DC-6DC5BCD44252
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics>{ 0xADD3468C,0xA273,0x48CB,{ 0xB3,0x46,0x35,0x44,0x52,0x2D,0x55,0x81 } }; // ADD3468C-A273-48CB-B346-3544522D5581
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2>{ 0xDD0947AF,0x1A6D,0x46B0,{ 0x95,0xBC,0xF3,0xF9,0xD6,0xBE,0xB9,0xFB } }; // DD0947AF-1A6D-46B0-95BC-F3F9D6BEB9FB
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IAssignedAccessSettings>{ 0x1BC57F1C,0xE971,0x5757,{ 0xB8,0xE0,0x51,0x2F,0x8B,0x8C,0x46,0xD2 } }; // 1BC57F1C-E971-5757-B8E0-512F8B8C46D2
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics>{ 0x34A81D0D,0x8A29,0x5EF3,{ 0xA7,0xBE,0x61,0x8E,0x6A,0xC3,0xBD,0x01 } }; // 34A81D0D-8A29-5EF3-A7BE-618E6AC3BD01
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IDiagnosticsSettings>{ 0xE5E9ECCD,0x2711,0x44E0,{ 0x97,0x3C,0x49,0x1D,0x78,0x04,0x8D,0x24 } }; // E5E9ECCD-2711-44E0-973C-491D78048D24
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics>{ 0x72D2E80F,0x5390,0x4793,{ 0x99,0x0B,0x3C,0xCC,0x7D,0x6A,0xC9,0xC8 } }; // 72D2E80F-5390-4793-990B-3CCC7D6AC9C8
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IFirstSignInSettings>{ 0x3E945153,0x3A5E,0x452E,{ 0xA6,0x01,0xF5,0xBA,0xAD,0x2A,0x48,0x70 } }; // 3E945153-3A5E-452E-A601-F5BAAD2A4870
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics>{ 0x1CE18F0F,0x1C41,0x4EA0,{ 0xB7,0xA2,0x6F,0x0C,0x1C,0x7E,0x84,0x38 } }; // 1CE18F0F-1C41-4EA0-B7A2-6F0C1C7E8438
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser>{ 0x150F0795,0x4F6E,0x40BA,{ 0xA0,0x10,0xE2,0x7D,0x81,0xBD,0xA7,0xF5 } }; // 150F0795-4F6E-40BA-A010-E27D81BDA7F5
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics>{ 0x01BF4326,0xED37,0x4E96,{ 0xB0,0xE9,0xC1,0x34,0x0D,0x1E,0xA1,0x58 } }; // 01BF4326-ED37-4E96-B0E9-C1340D1EA158
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2>{ 0xFCCE85F1,0x4300,0x4CD0,{ 0x9C,0xAC,0x1A,0x8E,0x7B,0x7E,0x18,0xF4 } }; // FCCE85F1-4300-4CD0-9CAC-1A8E7B7E18F4
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3>{ 0x1E059733,0x35F5,0x40D8,{ 0xB9,0xE8,0xAE,0xF3,0xEF,0x85,0x6F,0xCE } }; // 1E059733-35F5-40D8-B9E8-AEF3EF856FCE
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics>{ 0x2C0D73F6,0x03A9,0x41A6,{ 0x9B,0x01,0x49,0x52,0x51,0xFF,0x51,0xD5 } }; // 2C0D73F6-03A9-41A6-9B01-495251FF51D5
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::ILockScreenStatics>{ 0x3EE9D3AD,0xB607,0x40AE,{ 0xB4,0x26,0x76,0x31,0xD9,0x82,0x12,0x69 } }; // 3EE9D3AD-B607-40AE-B426-7631D9821269
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IUserInformationStatics>{ 0x77F3A910,0x48FA,0x489C,{ 0x93,0x4E,0x2A,0xE8,0x5B,0xA8,0xF7,0x72 } }; // 77F3A910-48FA-489C-934E-2AE85BA8F772
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings>{ 0x8CEDDAB4,0x7998,0x46D5,{ 0x8D,0xD3,0x18,0x4F,0x1C,0x5F,0x9A,0xB9 } }; // 8CEDDAB4-7998-46D5-8DD3-184F1C5F9AB9
    template <> inline constexpr guid guid_v<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>{ 0x91ACB841,0x5037,0x454B,{ 0x98,0x83,0xBB,0x77,0x2D,0x08,0xDD,0x16 } }; // 91ACB841-5037-454B-9883-BB772D08DD16
    template <> struct default_interface<winrt::Windows::System::UserProfile::AdvertisingManagerForUser>{ using type = winrt::Windows::System::UserProfile::IAdvertisingManagerForUser; };
    template <> struct default_interface<winrt::Windows::System::UserProfile::AssignedAccessSettings>{ using type = winrt::Windows::System::UserProfile::IAssignedAccessSettings; };
    template <> struct default_interface<winrt::Windows::System::UserProfile::DiagnosticsSettings>{ using type = winrt::Windows::System::UserProfile::IDiagnosticsSettings; };
    template <> struct default_interface<winrt::Windows::System::UserProfile::FirstSignInSettings>{ using type = winrt::Windows::System::UserProfile::IFirstSignInSettings; };
    template <> struct default_interface<winrt::Windows::System::UserProfile::GlobalizationPreferencesForUser>{ using type = winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser; };
    template <> struct default_interface<winrt::Windows::System::UserProfile::UserProfilePersonalizationSettings>{ using type = winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings; };
    template <> struct abi<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AdvertisingId(void**) noexcept = 0;
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AdvertisingId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IAssignedAccessSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSingleAppKioskMode(bool*) noexcept = 0;
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IDiagnosticsSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CanUseDiagnosticsToTailorExperiences(bool*) noexcept = 0;
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IFirstSignInSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
            virtual int32_t __stdcall get_Calendars(void**) noexcept = 0;
            virtual int32_t __stdcall get_Clocks(void**) noexcept = 0;
            virtual int32_t __stdcall get_Currencies(void**) noexcept = 0;
            virtual int32_t __stdcall get_Languages(void**) noexcept = 0;
            virtual int32_t __stdcall get_HomeGeographicRegion(void**) noexcept = 0;
            virtual int32_t __stdcall get_WeekStartsOn(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Calendars(void**) noexcept = 0;
            virtual int32_t __stdcall get_Clocks(void**) noexcept = 0;
            virtual int32_t __stdcall get_Currencies(void**) noexcept = 0;
            virtual int32_t __stdcall get_Languages(void**) noexcept = 0;
            virtual int32_t __stdcall get_HomeGeographicRegion(void**) noexcept = 0;
            virtual int32_t __stdcall get_WeekStartsOn(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TrySetHomeGeographicRegion(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall TrySetLanguages(void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestSetImageFeedAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryRemoveImageFeed(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::ILockScreenStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_OriginalImageFile(void**) noexcept = 0;
            virtual int32_t __stdcall GetImageStream(void**) noexcept = 0;
            virtual int32_t __stdcall SetImageFileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetImageStreamAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IUserInformationStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AccountPictureChangeEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_NameAccessAllowed(bool*) noexcept = 0;
            virtual int32_t __stdcall GetAccountPicture(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SetAccountPictureAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetAccountPicturesAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetAccountPictureFromStreamAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetAccountPicturesFromStreamsAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_AccountPictureChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AccountPictureChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall GetDisplayNameAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetFirstNameAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetLastNameAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetPrincipalNameAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetSessionInitiationProtocolUriAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetDomainNameAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TrySetLockScreenImageAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TrySetWallpaperImageAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Current(void**) noexcept = 0;
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IAdvertisingManagerForUser
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AdvertisingId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IAdvertisingManagerForUser>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IAdvertisingManagerForUser<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IAdvertisingManagerStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AdvertisingId() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IAdvertisingManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IAdvertisingManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::AdvertisingManagerForUser) GetForUser(winrt::Windows::System::User const& user) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IAdvertisingManagerStatics2>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IAdvertisingManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IAssignedAccessSettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSingleAppKioskMode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IAssignedAccessSettings>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IAssignedAccessSettings<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IAssignedAccessSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::AssignedAccessSettings) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::AssignedAccessSettings) GetForUser(winrt::Windows::System::User const& user) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IAssignedAccessSettingsStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IAssignedAccessSettingsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IDiagnosticsSettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanUseDiagnosticsToTailorExperiences() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IDiagnosticsSettings>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IDiagnosticsSettings<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IDiagnosticsSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::DiagnosticsSettings) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::DiagnosticsSettings) GetForUser(winrt::Windows::System::User const& user) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IDiagnosticsSettingsStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IDiagnosticsSettingsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IFirstSignInSettings
    {
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IFirstSignInSettings>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IFirstSignInSettings<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IFirstSignInSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::FirstSignInSettings) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IFirstSignInSettingsStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IFirstSignInSettingsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Calendars() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Clocks() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Currencies() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Languages() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HomeGeographicRegion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DayOfWeek) WeekStartsOn() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IGlobalizationPreferencesForUser>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesForUser<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Calendars() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Clocks() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Currencies() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Languages() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HomeGeographicRegion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DayOfWeek) WeekStartsOn() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics2
    {
        WINRT_IMPL_AUTO(bool) TrySetHomeGeographicRegion(param::hstring const& region) const;
        WINRT_IMPL_AUTO(bool) TrySetLanguages(param::iterable<hstring> const& languageTags) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics2>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::GlobalizationPreferencesForUser) GetForUser(winrt::Windows::System::User const& user) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IGlobalizationPreferencesStatics3>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IGlobalizationPreferencesStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_ILockScreenImageFeedStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserProfile::SetImageFeedResult>) RequestSetImageFeedAsync(winrt::Windows::Foundation::Uri const& syndicationFeedUri) const;
        WINRT_IMPL_AUTO(bool) TryRemoveImageFeed() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::ILockScreenImageFeedStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_ILockScreenImageFeedStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_ILockScreenStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) OriginalImageFile() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) GetImageStream() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetImageFileAsync(winrt::Windows::Storage::IStorageFile const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetImageStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& value) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::ILockScreenStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_ILockScreenStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IUserInformationStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AccountPictureChangeEnabled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) NameAccessAllowed() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) GetAccountPicture(winrt::Windows::System::UserProfile::AccountPictureKind const& kind) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserProfile::SetAccountPictureResult>) SetAccountPictureAsync(winrt::Windows::Storage::IStorageFile const& image) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserProfile::SetAccountPictureResult>) SetAccountPicturesAsync(winrt::Windows::Storage::IStorageFile const& smallImage, winrt::Windows::Storage::IStorageFile const& largeImage, winrt::Windows::Storage::IStorageFile const& video) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserProfile::SetAccountPictureResult>) SetAccountPictureFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& image) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserProfile::SetAccountPictureResult>) SetAccountPicturesFromStreamsAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& smallImage, winrt::Windows::Storage::Streams::IRandomAccessStream const& largeImage, winrt::Windows::Storage::Streams::IRandomAccessStream const& video) const;
        WINRT_IMPL_AUTO(winrt::event_token) AccountPictureChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& changeHandler) const;
        using AccountPictureChanged_revoker = impl::event_revoker<winrt::Windows::System::UserProfile::IUserInformationStatics, &impl::abi_t<winrt::Windows::System::UserProfile::IUserInformationStatics>::remove_AccountPictureChanged>;
        [[nodiscard]] AccountPictureChanged_revoker AccountPictureChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& changeHandler) const;
        WINRT_IMPL_AUTO(void) AccountPictureChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetDisplayNameAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetFirstNameAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetLastNameAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetPrincipalNameAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>) GetSessionInitiationProtocolUriAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetDomainNameAsync() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IUserInformationStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IUserInformationStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IUserProfilePersonalizationSettings
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TrySetLockScreenImageAsync(winrt::Windows::Storage::StorageFile const& imageFile) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TrySetWallpaperImageAsync(winrt::Windows::Storage::StorageFile const& imageFile) const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettings>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IUserProfilePersonalizationSettings<D>;
    };
    template <typename D>
    struct consume_Windows_System_UserProfile_IUserProfilePersonalizationSettingsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::UserProfile::UserProfilePersonalizationSettings) Current() const;
        WINRT_IMPL_AUTO(bool) IsSupported() const;
    };
    template <> struct consume<winrt::Windows::System::UserProfile::IUserProfilePersonalizationSettingsStatics>
    {
        template <typename D> using type = consume_Windows_System_UserProfile_IUserProfilePersonalizationSettingsStatics<D>;
    };
}
#endif
