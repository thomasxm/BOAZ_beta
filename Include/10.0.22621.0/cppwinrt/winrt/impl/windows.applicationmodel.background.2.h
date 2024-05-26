// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Background_2_H
#define WINRT_Windows_ApplicationModel_Background_2_H
#include "winrt/impl/Windows.ApplicationModel.Calls.Background.1.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Background.1.h"
#include "winrt/impl/Windows.Devices.Bluetooth.GenericAttributeProfile.1.h"
#include "winrt/impl/Windows.Devices.Sensors.1.h"
#include "winrt/impl/Windows.Devices.SmartCards.1.h"
#include "winrt/impl/Windows.Devices.Sms.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.UI.Notifications.1.h"
#include "winrt/impl/Windows.ApplicationModel.Background.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Background
{
    struct BackgroundTaskCanceledEventHandler : winrt::Windows::Foundation::IUnknown
    {
        BackgroundTaskCanceledEventHandler(std::nullptr_t = nullptr) noexcept {}
        BackgroundTaskCanceledEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> BackgroundTaskCanceledEventHandler(L lambda);
        template <typename F> BackgroundTaskCanceledEventHandler(F* function);
        template <typename O, typename M> BackgroundTaskCanceledEventHandler(O* object, M method);
        template <typename O, typename M> BackgroundTaskCanceledEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> BackgroundTaskCanceledEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance const& sender, winrt::Windows::ApplicationModel::Background::BackgroundTaskCancellationReason const& reason) const;
    };
    struct BackgroundTaskCompletedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        BackgroundTaskCompletedEventHandler(std::nullptr_t = nullptr) noexcept {}
        BackgroundTaskCompletedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> BackgroundTaskCompletedEventHandler(L lambda);
        template <typename F> BackgroundTaskCompletedEventHandler(F* function);
        template <typename O, typename M> BackgroundTaskCompletedEventHandler(O* object, M method);
        template <typename O, typename M> BackgroundTaskCompletedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> BackgroundTaskCompletedEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::ApplicationModel::Background::BackgroundTaskRegistration const& sender, winrt::Windows::ApplicationModel::Background::BackgroundTaskCompletedEventArgs const& args) const;
    };
    struct BackgroundTaskProgressEventHandler : winrt::Windows::Foundation::IUnknown
    {
        BackgroundTaskProgressEventHandler(std::nullptr_t = nullptr) noexcept {}
        BackgroundTaskProgressEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> BackgroundTaskProgressEventHandler(L lambda);
        template <typename F> BackgroundTaskProgressEventHandler(F* function);
        template <typename O, typename M> BackgroundTaskProgressEventHandler(O* object, M method);
        template <typename O, typename M> BackgroundTaskProgressEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> BackgroundTaskProgressEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::ApplicationModel::Background::BackgroundTaskRegistration const& sender, winrt::Windows::ApplicationModel::Background::BackgroundTaskProgressEventArgs const& args) const;
    };
    struct __declspec(empty_bases) ActivitySensorTrigger : winrt::Windows::ApplicationModel::Background::IActivitySensorTrigger
    {
        ActivitySensorTrigger(std::nullptr_t) noexcept {}
        ActivitySensorTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IActivitySensorTrigger(ptr, take_ownership_from_abi) {}
        explicit ActivitySensorTrigger(uint32_t reportIntervalInMilliseconds);
    };
    struct AlarmApplicationManager
    {
        AlarmApplicationManager() = delete;
        static auto RequestAccessAsync();
        static auto GetAccessStatus();
    };
    struct __declspec(empty_bases) AppBroadcastTrigger : winrt::Windows::ApplicationModel::Background::IAppBroadcastTrigger
    {
        AppBroadcastTrigger(std::nullptr_t) noexcept {}
        AppBroadcastTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IAppBroadcastTrigger(ptr, take_ownership_from_abi) {}
        explicit AppBroadcastTrigger(param::hstring const& providerKey);
    };
    struct __declspec(empty_bases) AppBroadcastTriggerProviderInfo : winrt::Windows::ApplicationModel::Background::IAppBroadcastTriggerProviderInfo
    {
        AppBroadcastTriggerProviderInfo(std::nullptr_t) noexcept {}
        AppBroadcastTriggerProviderInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IAppBroadcastTriggerProviderInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ApplicationTrigger : winrt::Windows::ApplicationModel::Background::IApplicationTrigger
    {
        ApplicationTrigger(std::nullptr_t) noexcept {}
        ApplicationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IApplicationTrigger(ptr, take_ownership_from_abi) {}
        ApplicationTrigger();
    };
    struct __declspec(empty_bases) ApplicationTriggerDetails : winrt::Windows::ApplicationModel::Background::IApplicationTriggerDetails
    {
        ApplicationTriggerDetails(std::nullptr_t) noexcept {}
        ApplicationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IApplicationTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppointmentStoreNotificationTrigger : winrt::Windows::ApplicationModel::Background::IAppointmentStoreNotificationTrigger
    {
        AppointmentStoreNotificationTrigger(std::nullptr_t) noexcept {}
        AppointmentStoreNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IAppointmentStoreNotificationTrigger(ptr, take_ownership_from_abi) {}
        AppointmentStoreNotificationTrigger();
    };
    struct BackgroundExecutionManager
    {
        BackgroundExecutionManager() = delete;
        static auto RequestAccessAsync();
        static auto RequestAccessAsync(param::hstring const& applicationId);
        static auto RemoveAccess();
        static auto RemoveAccess(param::hstring const& applicationId);
        static auto GetAccessStatus();
        static auto GetAccessStatus(param::hstring const& applicationId);
        static auto RequestAccessKindAsync(winrt::Windows::ApplicationModel::Background::BackgroundAccessRequestKind const& requestedAccess, param::hstring const& reason);
        static auto RequestAccessKindForModernStandbyAsync(winrt::Windows::ApplicationModel::Background::BackgroundAccessRequestKind const& requestedAccess, param::hstring const& reason);
        static auto GetAccessStatusForModernStandby();
        static auto GetAccessStatusForModernStandby(param::hstring const& applicationId);
    };
    struct __declspec(empty_bases) BackgroundTaskBuilder : winrt::Windows::ApplicationModel::Background::IBackgroundTaskBuilder,
        impl::require<BackgroundTaskBuilder, winrt::Windows::ApplicationModel::Background::IBackgroundTaskBuilder2, winrt::Windows::ApplicationModel::Background::IBackgroundTaskBuilder3, winrt::Windows::ApplicationModel::Background::IBackgroundTaskBuilder4, winrt::Windows::ApplicationModel::Background::IBackgroundTaskBuilder5>
    {
        BackgroundTaskBuilder(std::nullptr_t) noexcept {}
        BackgroundTaskBuilder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTaskBuilder(ptr, take_ownership_from_abi) {}
        BackgroundTaskBuilder();
    };
    struct __declspec(empty_bases) BackgroundTaskCompletedEventArgs : winrt::Windows::ApplicationModel::Background::IBackgroundTaskCompletedEventArgs
    {
        BackgroundTaskCompletedEventArgs(std::nullptr_t) noexcept {}
        BackgroundTaskCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTaskCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BackgroundTaskDeferral : winrt::Windows::ApplicationModel::Background::IBackgroundTaskDeferral
    {
        BackgroundTaskDeferral(std::nullptr_t) noexcept {}
        BackgroundTaskDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTaskDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BackgroundTaskProgressEventArgs : winrt::Windows::ApplicationModel::Background::IBackgroundTaskProgressEventArgs
    {
        BackgroundTaskProgressEventArgs(std::nullptr_t) noexcept {}
        BackgroundTaskProgressEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTaskProgressEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BackgroundTaskRegistration : winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration,
        impl::require<BackgroundTaskRegistration, winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration2, winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration3>
    {
        BackgroundTaskRegistration(std::nullptr_t) noexcept {}
        BackgroundTaskRegistration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto AllTasks();
        [[nodiscard]] static auto AllTaskGroups();
        static auto GetTaskGroup(param::hstring const& groupId);
    };
    struct __declspec(empty_bases) BackgroundTaskRegistrationGroup : winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistrationGroup
    {
        BackgroundTaskRegistrationGroup(std::nullptr_t) noexcept {}
        BackgroundTaskRegistrationGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistrationGroup(ptr, take_ownership_from_abi) {}
        explicit BackgroundTaskRegistrationGroup(param::hstring const& id);
        BackgroundTaskRegistrationGroup(param::hstring const& id, param::hstring const& name);
    };
    struct BackgroundWorkCost
    {
        BackgroundWorkCost() = delete;
        [[nodiscard]] static auto CurrentBackgroundWorkCost();
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementPublisherTrigger : winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementPublisherTrigger,
        impl::require<BluetoothLEAdvertisementPublisherTrigger, winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementPublisherTrigger2>
    {
        BluetoothLEAdvertisementPublisherTrigger(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementPublisherTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementPublisherTrigger(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementPublisherTrigger();
    };
    struct __declspec(empty_bases) BluetoothLEAdvertisementWatcherTrigger : winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementWatcherTrigger,
        impl::require<BluetoothLEAdvertisementWatcherTrigger, winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementWatcherTrigger2>
    {
        BluetoothLEAdvertisementWatcherTrigger(std::nullptr_t) noexcept {}
        BluetoothLEAdvertisementWatcherTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementWatcherTrigger(ptr, take_ownership_from_abi) {}
        BluetoothLEAdvertisementWatcherTrigger();
    };
    struct __declspec(empty_bases) CachedFileUpdaterTrigger : winrt::Windows::ApplicationModel::Background::ICachedFileUpdaterTrigger
    {
        CachedFileUpdaterTrigger(std::nullptr_t) noexcept {}
        CachedFileUpdaterTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ICachedFileUpdaterTrigger(ptr, take_ownership_from_abi) {}
        CachedFileUpdaterTrigger();
    };
    struct __declspec(empty_bases) CachedFileUpdaterTriggerDetails : winrt::Windows::ApplicationModel::Background::ICachedFileUpdaterTriggerDetails
    {
        CachedFileUpdaterTriggerDetails(std::nullptr_t) noexcept {}
        CachedFileUpdaterTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ICachedFileUpdaterTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ChatMessageNotificationTrigger : winrt::Windows::ApplicationModel::Background::IChatMessageNotificationTrigger
    {
        ChatMessageNotificationTrigger(std::nullptr_t) noexcept {}
        ChatMessageNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IChatMessageNotificationTrigger(ptr, take_ownership_from_abi) {}
        ChatMessageNotificationTrigger();
    };
    struct __declspec(empty_bases) ChatMessageReceivedNotificationTrigger : winrt::Windows::ApplicationModel::Background::IChatMessageReceivedNotificationTrigger
    {
        ChatMessageReceivedNotificationTrigger(std::nullptr_t) noexcept {}
        ChatMessageReceivedNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IChatMessageReceivedNotificationTrigger(ptr, take_ownership_from_abi) {}
        ChatMessageReceivedNotificationTrigger();
    };
    struct __declspec(empty_bases) CommunicationBlockingAppSetAsActiveTrigger : winrt::Windows::ApplicationModel::Background::ICommunicationBlockingAppSetAsActiveTrigger
    {
        CommunicationBlockingAppSetAsActiveTrigger(std::nullptr_t) noexcept {}
        CommunicationBlockingAppSetAsActiveTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ICommunicationBlockingAppSetAsActiveTrigger(ptr, take_ownership_from_abi) {}
        CommunicationBlockingAppSetAsActiveTrigger();
    };
    struct __declspec(empty_bases) ContactStoreNotificationTrigger : winrt::Windows::ApplicationModel::Background::IContactStoreNotificationTrigger
    {
        ContactStoreNotificationTrigger(std::nullptr_t) noexcept {}
        ContactStoreNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IContactStoreNotificationTrigger(ptr, take_ownership_from_abi) {}
        ContactStoreNotificationTrigger();
    };
    struct __declspec(empty_bases) ContentPrefetchTrigger : winrt::Windows::ApplicationModel::Background::IContentPrefetchTrigger
    {
        ContentPrefetchTrigger(std::nullptr_t) noexcept {}
        ContentPrefetchTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IContentPrefetchTrigger(ptr, take_ownership_from_abi) {}
        ContentPrefetchTrigger();
        explicit ContentPrefetchTrigger(winrt::Windows::Foundation::TimeSpan const& waitInterval);
    };
    struct __declspec(empty_bases) ConversationalAgentTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        ConversationalAgentTrigger(std::nullptr_t) noexcept {}
        ConversationalAgentTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        ConversationalAgentTrigger();
    };
    struct __declspec(empty_bases) CustomSystemEventTrigger : winrt::Windows::ApplicationModel::Background::ICustomSystemEventTrigger,
        impl::require<CustomSystemEventTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        CustomSystemEventTrigger(std::nullptr_t) noexcept {}
        CustomSystemEventTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ICustomSystemEventTrigger(ptr, take_ownership_from_abi) {}
        CustomSystemEventTrigger(param::hstring const& triggerId, winrt::Windows::ApplicationModel::Background::CustomSystemEventTriggerRecurrence const& recurrence);
    };
    struct __declspec(empty_bases) DeviceConnectionChangeTrigger : winrt::Windows::ApplicationModel::Background::IDeviceConnectionChangeTrigger
    {
        DeviceConnectionChangeTrigger(std::nullptr_t) noexcept {}
        DeviceConnectionChangeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IDeviceConnectionChangeTrigger(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(param::hstring const& deviceId);
    };
    struct __declspec(empty_bases) DeviceManufacturerNotificationTrigger : winrt::Windows::ApplicationModel::Background::IDeviceManufacturerNotificationTrigger
    {
        DeviceManufacturerNotificationTrigger(std::nullptr_t) noexcept {}
        DeviceManufacturerNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IDeviceManufacturerNotificationTrigger(ptr, take_ownership_from_abi) {}
        DeviceManufacturerNotificationTrigger(param::hstring const& triggerQualifier, bool oneShot);
    };
    struct __declspec(empty_bases) DeviceServicingTrigger : winrt::Windows::ApplicationModel::Background::IDeviceServicingTrigger
    {
        DeviceServicingTrigger(std::nullptr_t) noexcept {}
        DeviceServicingTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IDeviceServicingTrigger(ptr, take_ownership_from_abi) {}
        DeviceServicingTrigger();
    };
    struct __declspec(empty_bases) DeviceUseTrigger : winrt::Windows::ApplicationModel::Background::IDeviceUseTrigger
    {
        DeviceUseTrigger(std::nullptr_t) noexcept {}
        DeviceUseTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IDeviceUseTrigger(ptr, take_ownership_from_abi) {}
        DeviceUseTrigger();
    };
    struct __declspec(empty_bases) DeviceWatcherTrigger : winrt::Windows::ApplicationModel::Background::IDeviceWatcherTrigger
    {
        DeviceWatcherTrigger(std::nullptr_t) noexcept {}
        DeviceWatcherTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IDeviceWatcherTrigger(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) EmailStoreNotificationTrigger : winrt::Windows::ApplicationModel::Background::IEmailStoreNotificationTrigger
    {
        EmailStoreNotificationTrigger(std::nullptr_t) noexcept {}
        EmailStoreNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IEmailStoreNotificationTrigger(ptr, take_ownership_from_abi) {}
        EmailStoreNotificationTrigger();
    };
    struct __declspec(empty_bases) GattCharacteristicNotificationTrigger : winrt::Windows::ApplicationModel::Background::IGattCharacteristicNotificationTrigger,
        impl::require<GattCharacteristicNotificationTrigger, winrt::Windows::ApplicationModel::Background::IGattCharacteristicNotificationTrigger2>
    {
        GattCharacteristicNotificationTrigger(std::nullptr_t) noexcept {}
        GattCharacteristicNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IGattCharacteristicNotificationTrigger(ptr, take_ownership_from_abi) {}
        explicit GattCharacteristicNotificationTrigger(winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic const& characteristic);
        GattCharacteristicNotificationTrigger(winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic const& characteristic, winrt::Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode const& eventTriggeringMode);
    };
    struct __declspec(empty_bases) GattServiceProviderTrigger : winrt::Windows::ApplicationModel::Background::IGattServiceProviderTrigger,
        impl::require<GattServiceProviderTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        GattServiceProviderTrigger(std::nullptr_t) noexcept {}
        GattServiceProviderTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IGattServiceProviderTrigger(ptr, take_ownership_from_abi) {}
        static auto CreateAsync(param::hstring const& triggerId, winrt::guid const& serviceUuid);
    };
    struct __declspec(empty_bases) GattServiceProviderTriggerResult : winrt::Windows::ApplicationModel::Background::IGattServiceProviderTriggerResult
    {
        GattServiceProviderTriggerResult(std::nullptr_t) noexcept {}
        GattServiceProviderTriggerResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IGattServiceProviderTriggerResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) GeovisitTrigger : winrt::Windows::ApplicationModel::Background::IGeovisitTrigger
    {
        GeovisitTrigger(std::nullptr_t) noexcept {}
        GeovisitTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IGeovisitTrigger(ptr, take_ownership_from_abi) {}
        GeovisitTrigger();
    };
    struct __declspec(empty_bases) LocationTrigger : winrt::Windows::ApplicationModel::Background::ILocationTrigger
    {
        LocationTrigger(std::nullptr_t) noexcept {}
        LocationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ILocationTrigger(ptr, take_ownership_from_abi) {}
        explicit LocationTrigger(winrt::Windows::ApplicationModel::Background::LocationTriggerType const& triggerType);
    };
    struct __declspec(empty_bases) MaintenanceTrigger : winrt::Windows::ApplicationModel::Background::IMaintenanceTrigger
    {
        MaintenanceTrigger(std::nullptr_t) noexcept {}
        MaintenanceTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IMaintenanceTrigger(ptr, take_ownership_from_abi) {}
        MaintenanceTrigger(uint32_t freshnessTime, bool oneShot);
    };
    struct __declspec(empty_bases) MediaProcessingTrigger : winrt::Windows::ApplicationModel::Background::IMediaProcessingTrigger
    {
        MediaProcessingTrigger(std::nullptr_t) noexcept {}
        MediaProcessingTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IMediaProcessingTrigger(ptr, take_ownership_from_abi) {}
        MediaProcessingTrigger();
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceNotificationTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        MobileBroadbandDeviceServiceNotificationTrigger(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        MobileBroadbandDeviceServiceNotificationTrigger();
    };
    struct __declspec(empty_bases) MobileBroadbandPcoDataChangeTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        MobileBroadbandPcoDataChangeTrigger(std::nullptr_t) noexcept {}
        MobileBroadbandPcoDataChangeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        MobileBroadbandPcoDataChangeTrigger();
    };
    struct __declspec(empty_bases) MobileBroadbandPinLockStateChangeTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        MobileBroadbandPinLockStateChangeTrigger(std::nullptr_t) noexcept {}
        MobileBroadbandPinLockStateChangeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        MobileBroadbandPinLockStateChangeTrigger();
    };
    struct __declspec(empty_bases) MobileBroadbandRadioStateChangeTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        MobileBroadbandRadioStateChangeTrigger(std::nullptr_t) noexcept {}
        MobileBroadbandRadioStateChangeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        MobileBroadbandRadioStateChangeTrigger();
    };
    struct __declspec(empty_bases) MobileBroadbandRegistrationStateChangeTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        MobileBroadbandRegistrationStateChangeTrigger(std::nullptr_t) noexcept {}
        MobileBroadbandRegistrationStateChangeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        MobileBroadbandRegistrationStateChangeTrigger();
    };
    struct __declspec(empty_bases) NetworkOperatorDataUsageTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        NetworkOperatorDataUsageTrigger(std::nullptr_t) noexcept {}
        NetworkOperatorDataUsageTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        NetworkOperatorDataUsageTrigger();
    };
    struct __declspec(empty_bases) NetworkOperatorHotspotAuthenticationTrigger : winrt::Windows::ApplicationModel::Background::INetworkOperatorHotspotAuthenticationTrigger
    {
        NetworkOperatorHotspotAuthenticationTrigger(std::nullptr_t) noexcept {}
        NetworkOperatorHotspotAuthenticationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::INetworkOperatorHotspotAuthenticationTrigger(ptr, take_ownership_from_abi) {}
        NetworkOperatorHotspotAuthenticationTrigger();
    };
    struct __declspec(empty_bases) NetworkOperatorNotificationTrigger : winrt::Windows::ApplicationModel::Background::INetworkOperatorNotificationTrigger
    {
        NetworkOperatorNotificationTrigger(std::nullptr_t) noexcept {}
        NetworkOperatorNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::INetworkOperatorNotificationTrigger(ptr, take_ownership_from_abi) {}
        explicit NetworkOperatorNotificationTrigger(param::hstring const& networkAccountId);
    };
    struct __declspec(empty_bases) PaymentAppCanMakePaymentTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        PaymentAppCanMakePaymentTrigger(std::nullptr_t) noexcept {}
        PaymentAppCanMakePaymentTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        PaymentAppCanMakePaymentTrigger();
    };
    struct __declspec(empty_bases) PhoneTrigger : winrt::Windows::ApplicationModel::Background::IPhoneTrigger
    {
        PhoneTrigger(std::nullptr_t) noexcept {}
        PhoneTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IPhoneTrigger(ptr, take_ownership_from_abi) {}
        PhoneTrigger(winrt::Windows::ApplicationModel::Calls::Background::PhoneTriggerType const& type, bool oneShot);
    };
    struct __declspec(empty_bases) PushNotificationTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        PushNotificationTrigger(std::nullptr_t) noexcept {}
        PushNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        PushNotificationTrigger();
        explicit PushNotificationTrigger(param::hstring const& applicationId);
    };
    struct __declspec(empty_bases) RcsEndUserMessageAvailableTrigger : winrt::Windows::ApplicationModel::Background::IRcsEndUserMessageAvailableTrigger
    {
        RcsEndUserMessageAvailableTrigger(std::nullptr_t) noexcept {}
        RcsEndUserMessageAvailableTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IRcsEndUserMessageAvailableTrigger(ptr, take_ownership_from_abi) {}
        RcsEndUserMessageAvailableTrigger();
    };
    struct __declspec(empty_bases) RfcommConnectionTrigger : winrt::Windows::ApplicationModel::Background::IRfcommConnectionTrigger
    {
        RfcommConnectionTrigger(std::nullptr_t) noexcept {}
        RfcommConnectionTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IRfcommConnectionTrigger(ptr, take_ownership_from_abi) {}
        RfcommConnectionTrigger();
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorAuthenticationTrigger : winrt::Windows::ApplicationModel::Background::ISecondaryAuthenticationFactorAuthenticationTrigger
    {
        SecondaryAuthenticationFactorAuthenticationTrigger(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorAuthenticationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ISecondaryAuthenticationFactorAuthenticationTrigger(ptr, take_ownership_from_abi) {}
        SecondaryAuthenticationFactorAuthenticationTrigger();
    };
    struct __declspec(empty_bases) SensorDataThresholdTrigger : winrt::Windows::ApplicationModel::Background::ISensorDataThresholdTrigger
    {
        SensorDataThresholdTrigger(std::nullptr_t) noexcept {}
        SensorDataThresholdTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ISensorDataThresholdTrigger(ptr, take_ownership_from_abi) {}
        explicit SensorDataThresholdTrigger(winrt::Windows::Devices::Sensors::ISensorDataThreshold const& threshold);
    };
    struct __declspec(empty_bases) SmartCardTrigger : winrt::Windows::ApplicationModel::Background::ISmartCardTrigger
    {
        SmartCardTrigger(std::nullptr_t) noexcept {}
        SmartCardTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ISmartCardTrigger(ptr, take_ownership_from_abi) {}
        explicit SmartCardTrigger(winrt::Windows::Devices::SmartCards::SmartCardTriggerType const& triggerType);
    };
    struct __declspec(empty_bases) SmsMessageReceivedTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        SmsMessageReceivedTrigger(std::nullptr_t) noexcept {}
        SmsMessageReceivedTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        explicit SmsMessageReceivedTrigger(winrt::Windows::Devices::Sms::SmsFilterRules const& filterRules);
    };
    struct __declspec(empty_bases) SocketActivityTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger,
        impl::require<SocketActivityTrigger, winrt::Windows::ApplicationModel::Background::ISocketActivityTrigger>
    {
        SocketActivityTrigger(std::nullptr_t) noexcept {}
        SocketActivityTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        SocketActivityTrigger();
    };
    struct __declspec(empty_bases) StorageLibraryChangeTrackerTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        StorageLibraryChangeTrackerTrigger(std::nullptr_t) noexcept {}
        StorageLibraryChangeTrackerTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        explicit StorageLibraryChangeTrackerTrigger(winrt::Windows::Storage::StorageLibraryChangeTracker const& tracker);
    };
    struct __declspec(empty_bases) StorageLibraryContentChangedTrigger : winrt::Windows::ApplicationModel::Background::IStorageLibraryContentChangedTrigger
    {
        StorageLibraryContentChangedTrigger(std::nullptr_t) noexcept {}
        StorageLibraryContentChangedTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IStorageLibraryContentChangedTrigger(ptr, take_ownership_from_abi) {}
        static auto Create(winrt::Windows::Storage::StorageLibrary const& storageLibrary);
        static auto CreateFromLibraries(param::iterable<winrt::Windows::Storage::StorageLibrary> const& storageLibraries);
    };
    struct __declspec(empty_bases) SystemCondition : winrt::Windows::ApplicationModel::Background::ISystemCondition
    {
        SystemCondition(std::nullptr_t) noexcept {}
        SystemCondition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ISystemCondition(ptr, take_ownership_from_abi) {}
        explicit SystemCondition(winrt::Windows::ApplicationModel::Background::SystemConditionType const& conditionType);
    };
    struct __declspec(empty_bases) SystemTrigger : winrt::Windows::ApplicationModel::Background::ISystemTrigger
    {
        SystemTrigger(std::nullptr_t) noexcept {}
        SystemTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ISystemTrigger(ptr, take_ownership_from_abi) {}
        SystemTrigger(winrt::Windows::ApplicationModel::Background::SystemTriggerType const& triggerType, bool oneShot);
    };
    struct __declspec(empty_bases) TetheringEntitlementCheckTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        TetheringEntitlementCheckTrigger(std::nullptr_t) noexcept {}
        TetheringEntitlementCheckTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        TetheringEntitlementCheckTrigger();
    };
    struct __declspec(empty_bases) TimeTrigger : winrt::Windows::ApplicationModel::Background::ITimeTrigger
    {
        TimeTrigger(std::nullptr_t) noexcept {}
        TimeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::ITimeTrigger(ptr, take_ownership_from_abi) {}
        TimeTrigger(uint32_t freshnessTime, bool oneShot);
    };
    struct __declspec(empty_bases) ToastNotificationActionTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        ToastNotificationActionTrigger(std::nullptr_t) noexcept {}
        ToastNotificationActionTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        ToastNotificationActionTrigger();
        explicit ToastNotificationActionTrigger(param::hstring const& applicationId);
    };
    struct __declspec(empty_bases) ToastNotificationHistoryChangedTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        ToastNotificationHistoryChangedTrigger(std::nullptr_t) noexcept {}
        ToastNotificationHistoryChangedTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        ToastNotificationHistoryChangedTrigger();
        explicit ToastNotificationHistoryChangedTrigger(param::hstring const& applicationId);
    };
    struct __declspec(empty_bases) UserNotificationChangedTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        UserNotificationChangedTrigger(std::nullptr_t) noexcept {}
        UserNotificationChangedTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        explicit UserNotificationChangedTrigger(winrt::Windows::UI::Notifications::NotificationKinds const& notificationKinds);
    };
    struct __declspec(empty_bases) WiFiOnDemandHotspotConnectTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        WiFiOnDemandHotspotConnectTrigger(std::nullptr_t) noexcept {}
        WiFiOnDemandHotspotConnectTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        WiFiOnDemandHotspotConnectTrigger();
    };
    struct __declspec(empty_bases) WiFiOnDemandHotspotUpdateMetadataTrigger : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger
    {
        WiFiOnDemandHotspotUpdateMetadataTrigger(std::nullptr_t) noexcept {}
        WiFiOnDemandHotspotUpdateMetadataTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Background::IBackgroundTrigger(ptr, take_ownership_from_abi) {}
        WiFiOnDemandHotspotUpdateMetadataTrigger();
    };
}
#endif
