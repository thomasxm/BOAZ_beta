// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_2_H
#define WINRT_Windows_UI_Notifications_2_H
#include "winrt/impl/Windows.Data.Xml.Dom.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.Notifications.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Notifications
{
    struct __declspec(empty_bases) AdaptiveNotificationText : winrt::Windows::UI::Notifications::IAdaptiveNotificationText,
        impl::require<AdaptiveNotificationText, winrt::Windows::UI::Notifications::IAdaptiveNotificationContent>
    {
        AdaptiveNotificationText(std::nullptr_t) noexcept {}
        AdaptiveNotificationText(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IAdaptiveNotificationText(ptr, take_ownership_from_abi) {}
        AdaptiveNotificationText();
    };
    struct __declspec(empty_bases) BadgeNotification : winrt::Windows::UI::Notifications::IBadgeNotification
    {
        BadgeNotification(std::nullptr_t) noexcept {}
        BadgeNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IBadgeNotification(ptr, take_ownership_from_abi) {}
        explicit BadgeNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content);
    };
    struct BadgeUpdateManager
    {
        BadgeUpdateManager() = delete;
        static auto CreateBadgeUpdaterForApplication();
        static auto CreateBadgeUpdaterForApplication(param::hstring const& applicationId);
        static auto CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId);
        static auto GetTemplateContent(winrt::Windows::UI::Notifications::BadgeTemplateType const& type);
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) BadgeUpdateManagerForUser : winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser
    {
        BadgeUpdateManagerForUser(std::nullptr_t) noexcept {}
        BadgeUpdateManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BadgeUpdater : winrt::Windows::UI::Notifications::IBadgeUpdater
    {
        BadgeUpdater(std::nullptr_t) noexcept {}
        BadgeUpdater(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IBadgeUpdater(ptr, take_ownership_from_abi) {}
    };
    struct KnownAdaptiveNotificationHints
    {
        KnownAdaptiveNotificationHints() = delete;
        [[nodiscard]] static auto Style();
        [[nodiscard]] static auto Wrap();
        [[nodiscard]] static auto MaxLines();
        [[nodiscard]] static auto MinLines();
        [[nodiscard]] static auto TextStacking();
        [[nodiscard]] static auto Align();
    };
    struct KnownAdaptiveNotificationTextStyles
    {
        KnownAdaptiveNotificationTextStyles() = delete;
        [[nodiscard]] static auto Caption();
        [[nodiscard]] static auto Body();
        [[nodiscard]] static auto Base();
        [[nodiscard]] static auto Subtitle();
        [[nodiscard]] static auto Title();
        [[nodiscard]] static auto Subheader();
        [[nodiscard]] static auto Header();
        [[nodiscard]] static auto TitleNumeral();
        [[nodiscard]] static auto SubheaderNumeral();
        [[nodiscard]] static auto HeaderNumeral();
        [[nodiscard]] static auto CaptionSubtle();
        [[nodiscard]] static auto BodySubtle();
        [[nodiscard]] static auto BaseSubtle();
        [[nodiscard]] static auto SubtitleSubtle();
        [[nodiscard]] static auto TitleSubtle();
        [[nodiscard]] static auto SubheaderSubtle();
        [[nodiscard]] static auto SubheaderNumeralSubtle();
        [[nodiscard]] static auto HeaderSubtle();
        [[nodiscard]] static auto HeaderNumeralSubtle();
    };
    struct KnownNotificationBindings
    {
        KnownNotificationBindings() = delete;
        [[nodiscard]] static auto ToastGeneric();
    };
    struct __declspec(empty_bases) Notification : winrt::Windows::UI::Notifications::INotification
    {
        Notification(std::nullptr_t) noexcept {}
        Notification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::INotification(ptr, take_ownership_from_abi) {}
        Notification();
    };
    struct __declspec(empty_bases) NotificationBinding : winrt::Windows::UI::Notifications::INotificationBinding
    {
        NotificationBinding(std::nullptr_t) noexcept {}
        NotificationBinding(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::INotificationBinding(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) NotificationData : winrt::Windows::UI::Notifications::INotificationData
    {
        NotificationData(std::nullptr_t) noexcept {}
        NotificationData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::INotificationData(ptr, take_ownership_from_abi) {}
        NotificationData();
        NotificationData(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues, uint32_t sequenceNumber);
        explicit NotificationData(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues);
    };
    struct __declspec(empty_bases) NotificationVisual : winrt::Windows::UI::Notifications::INotificationVisual
    {
        NotificationVisual(std::nullptr_t) noexcept {}
        NotificationVisual(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::INotificationVisual(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ScheduledTileNotification : winrt::Windows::UI::Notifications::IScheduledTileNotification
    {
        ScheduledTileNotification(std::nullptr_t) noexcept {}
        ScheduledTileNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IScheduledTileNotification(ptr, take_ownership_from_abi) {}
        ScheduledTileNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime);
    };
    struct __declspec(empty_bases) ScheduledToastNotification : winrt::Windows::UI::Notifications::IScheduledToastNotification,
        impl::require<ScheduledToastNotification, winrt::Windows::UI::Notifications::IScheduledToastNotification2, winrt::Windows::UI::Notifications::IScheduledToastNotification3, winrt::Windows::UI::Notifications::IScheduledToastNotification4>
    {
        ScheduledToastNotification(std::nullptr_t) noexcept {}
        ScheduledToastNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IScheduledToastNotification(ptr, take_ownership_from_abi) {}
        ScheduledToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime);
        ScheduledToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime, winrt::Windows::Foundation::TimeSpan const& snoozeInterval, uint32_t maximumSnoozeCount);
    };
    struct __declspec(empty_bases) ScheduledToastNotificationShowingEventArgs : winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs
    {
        ScheduledToastNotificationShowingEventArgs(std::nullptr_t) noexcept {}
        ScheduledToastNotificationShowingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShownTileNotification : winrt::Windows::UI::Notifications::IShownTileNotification
    {
        ShownTileNotification(std::nullptr_t) noexcept {}
        ShownTileNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IShownTileNotification(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) TileFlyoutNotification : winrt::Windows::UI::Notifications::ITileFlyoutNotification
    {
        TileFlyoutNotification(std::nullptr_t) noexcept {}
        TileFlyoutNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::ITileFlyoutNotification(ptr, take_ownership_from_abi) {}
        explicit TileFlyoutNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content);
    };
    struct TileFlyoutUpdateManager
    {
        TileFlyoutUpdateManager() = delete;
        static auto CreateTileFlyoutUpdaterForApplication();
        static auto CreateTileFlyoutUpdaterForApplication(param::hstring const& applicationId);
        static auto CreateTileFlyoutUpdaterForSecondaryTile(param::hstring const& tileId);
        static auto GetTemplateContent(winrt::Windows::UI::Notifications::TileFlyoutTemplateType const& type);
    };
    struct __declspec(empty_bases) TileFlyoutUpdater : winrt::Windows::UI::Notifications::ITileFlyoutUpdater
    {
        TileFlyoutUpdater(std::nullptr_t) noexcept {}
        TileFlyoutUpdater(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::ITileFlyoutUpdater(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) TileNotification : winrt::Windows::UI::Notifications::ITileNotification
    {
        TileNotification(std::nullptr_t) noexcept {}
        TileNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::ITileNotification(ptr, take_ownership_from_abi) {}
        explicit TileNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content);
    };
    struct TileUpdateManager
    {
        TileUpdateManager() = delete;
        static auto CreateTileUpdaterForApplication();
        static auto CreateTileUpdaterForApplication(param::hstring const& applicationId);
        static auto CreateTileUpdaterForSecondaryTile(param::hstring const& tileId);
        static auto GetTemplateContent(winrt::Windows::UI::Notifications::TileTemplateType const& type);
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) TileUpdateManagerForUser : winrt::Windows::UI::Notifications::ITileUpdateManagerForUser
    {
        TileUpdateManagerForUser(std::nullptr_t) noexcept {}
        TileUpdateManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::ITileUpdateManagerForUser(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) TileUpdater : winrt::Windows::UI::Notifications::ITileUpdater,
        impl::require<TileUpdater, winrt::Windows::UI::Notifications::ITileUpdater2>
    {
        TileUpdater(std::nullptr_t) noexcept {}
        TileUpdater(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::ITileUpdater(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastActivatedEventArgs : winrt::Windows::UI::Notifications::IToastActivatedEventArgs,
        impl::require<ToastActivatedEventArgs, winrt::Windows::UI::Notifications::IToastActivatedEventArgs2>
    {
        ToastActivatedEventArgs(std::nullptr_t) noexcept {}
        ToastActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastCollection : winrt::Windows::UI::Notifications::IToastCollection
    {
        ToastCollection(std::nullptr_t) noexcept {}
        ToastCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastCollection(ptr, take_ownership_from_abi) {}
        ToastCollection(param::hstring const& collectionId, param::hstring const& displayName, param::hstring const& launchArgs, winrt::Windows::Foundation::Uri const& iconUri);
    };
    struct __declspec(empty_bases) ToastCollectionManager : winrt::Windows::UI::Notifications::IToastCollectionManager
    {
        ToastCollectionManager(std::nullptr_t) noexcept {}
        ToastCollectionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastCollectionManager(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastDismissedEventArgs : winrt::Windows::UI::Notifications::IToastDismissedEventArgs
    {
        ToastDismissedEventArgs(std::nullptr_t) noexcept {}
        ToastDismissedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastDismissedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastFailedEventArgs : winrt::Windows::UI::Notifications::IToastFailedEventArgs
    {
        ToastFailedEventArgs(std::nullptr_t) noexcept {}
        ToastFailedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastFailedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastNotification : winrt::Windows::UI::Notifications::IToastNotification,
        impl::require<ToastNotification, winrt::Windows::UI::Notifications::IToastNotification2, winrt::Windows::UI::Notifications::IToastNotification3, winrt::Windows::UI::Notifications::IToastNotification4, winrt::Windows::UI::Notifications::IToastNotification6>
    {
        ToastNotification(std::nullptr_t) noexcept {}
        ToastNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastNotification(ptr, take_ownership_from_abi) {}
        explicit ToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content);
    };
    struct __declspec(empty_bases) ToastNotificationActionTriggerDetail : winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail
    {
        ToastNotificationActionTriggerDetail(std::nullptr_t) noexcept {}
        ToastNotificationActionTriggerDetail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastNotificationHistory : winrt::Windows::UI::Notifications::IToastNotificationHistory,
        impl::require<ToastNotificationHistory, winrt::Windows::UI::Notifications::IToastNotificationHistory2>
    {
        ToastNotificationHistory(std::nullptr_t) noexcept {}
        ToastNotificationHistory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastNotificationHistory(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastNotificationHistoryChangedTriggerDetail : winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail,
        impl::require<ToastNotificationHistoryChangedTriggerDetail, winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2>
    {
        ToastNotificationHistoryChangedTriggerDetail(std::nullptr_t) noexcept {}
        ToastNotificationHistoryChangedTriggerDetail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail(ptr, take_ownership_from_abi) {}
    };
    struct ToastNotificationManager
    {
        ToastNotificationManager() = delete;
        static auto CreateToastNotifier();
        static auto CreateToastNotifier(param::hstring const& applicationId);
        static auto GetTemplateContent(winrt::Windows::UI::Notifications::ToastTemplateType const& type);
        [[nodiscard]] static auto History();
        static auto GetForUser(winrt::Windows::System::User const& user);
        static auto ConfigureNotificationMirroring(winrt::Windows::UI::Notifications::NotificationMirroring const& value);
        static auto GetDefault();
    };
    struct __declspec(empty_bases) ToastNotificationManagerForUser : winrt::Windows::UI::Notifications::IToastNotificationManagerForUser,
        impl::require<ToastNotificationManagerForUser, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3>
    {
        ToastNotificationManagerForUser(std::nullptr_t) noexcept {}
        ToastNotificationManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastNotificationManagerForUser(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastNotifier : winrt::Windows::UI::Notifications::IToastNotifier,
        impl::require<ToastNotifier, winrt::Windows::UI::Notifications::IToastNotifier2, winrt::Windows::UI::Notifications::IToastNotifier3>
    {
        ToastNotifier(std::nullptr_t) noexcept {}
        ToastNotifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IToastNotifier(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserNotification : winrt::Windows::UI::Notifications::IUserNotification
    {
        UserNotification(std::nullptr_t) noexcept {}
        UserNotification(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IUserNotification(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserNotificationChangedEventArgs : winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs
    {
        UserNotificationChangedEventArgs(std::nullptr_t) noexcept {}
        UserNotificationChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
