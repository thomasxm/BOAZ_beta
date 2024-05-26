// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Background_1_H
#define WINRT_Windows_ApplicationModel_Background_1_H
#include "winrt/impl/Windows.ApplicationModel.Background.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Background
{
    struct __declspec(empty_bases) IActivitySensorTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IActivitySensorTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IActivitySensorTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IActivitySensorTrigger(std::nullptr_t = nullptr) noexcept {}
        IActivitySensorTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IActivitySensorTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IActivitySensorTriggerFactory>
    {
        IActivitySensorTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IActivitySensorTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAlarmApplicationManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAlarmApplicationManagerStatics>
    {
        IAlarmApplicationManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IAlarmApplicationManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppBroadcastTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppBroadcastTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IAppBroadcastTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IAppBroadcastTrigger(std::nullptr_t = nullptr) noexcept {}
        IAppBroadcastTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppBroadcastTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppBroadcastTriggerFactory>
    {
        IAppBroadcastTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IAppBroadcastTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppBroadcastTriggerProviderInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppBroadcastTriggerProviderInfo>
    {
        IAppBroadcastTriggerProviderInfo(std::nullptr_t = nullptr) noexcept {}
        IAppBroadcastTriggerProviderInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IApplicationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IApplicationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IApplicationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IApplicationTrigger(std::nullptr_t = nullptr) noexcept {}
        IApplicationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IApplicationTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IApplicationTriggerDetails>
    {
        IApplicationTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IApplicationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppointmentStoreNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppointmentStoreNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IAppointmentStoreNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IAppointmentStoreNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IAppointmentStoreNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundCondition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundCondition>
    {
        IBackgroundCondition(std::nullptr_t = nullptr) noexcept {}
        IBackgroundCondition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundExecutionManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundExecutionManagerStatics>
    {
        IBackgroundExecutionManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IBackgroundExecutionManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundExecutionManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundExecutionManagerStatics2>
    {
        IBackgroundExecutionManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IBackgroundExecutionManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundExecutionManagerStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundExecutionManagerStatics3>
    {
        IBackgroundExecutionManagerStatics3(std::nullptr_t = nullptr) noexcept {}
        IBackgroundExecutionManagerStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTask :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTask>
    {
        IBackgroundTask(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTask(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskBuilder :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskBuilder>
    {
        IBackgroundTaskBuilder(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskBuilder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskBuilder2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskBuilder2>
    {
        IBackgroundTaskBuilder2(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskBuilder2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskBuilder3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskBuilder3>
    {
        IBackgroundTaskBuilder3(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskBuilder3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskBuilder4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskBuilder4>
    {
        IBackgroundTaskBuilder4(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskBuilder4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskBuilder5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskBuilder5>
    {
        IBackgroundTaskBuilder5(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskBuilder5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskCompletedEventArgs>
    {
        IBackgroundTaskCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskDeferral>
    {
        IBackgroundTaskDeferral(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskInstance :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskInstance>
    {
        IBackgroundTaskInstance(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskInstance(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskInstance2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskInstance2>,
        impl::require<winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance2, winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance>
    {
        IBackgroundTaskInstance2(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskInstance2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskInstance4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskInstance4>,
        impl::require<winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance4, winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance>
    {
        IBackgroundTaskInstance4(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskInstance4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskProgressEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskProgressEventArgs>
    {
        IBackgroundTaskProgressEventArgs(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskProgressEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistration>
    {
        IBackgroundTaskRegistration(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistration2>,
        impl::require<winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration2, winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration>
    {
        IBackgroundTaskRegistration2(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistration3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistration3>,
        impl::require<winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration3, winrt::Windows::ApplicationModel::Background::IBackgroundTaskRegistration>
    {
        IBackgroundTaskRegistration3(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistration3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistrationGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistrationGroup>
    {
        IBackgroundTaskRegistrationGroup(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistrationGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistrationGroupFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistrationGroupFactory>
    {
        IBackgroundTaskRegistrationGroupFactory(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistrationGroupFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistrationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistrationStatics>
    {
        IBackgroundTaskRegistrationStatics(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistrationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTaskRegistrationStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTaskRegistrationStatics2>
    {
        IBackgroundTaskRegistrationStatics2(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTaskRegistrationStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundTrigger>
    {
        IBackgroundTrigger(std::nullptr_t = nullptr) noexcept {}
        IBackgroundTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackgroundWorkCostStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundWorkCostStatics>
    {
        IBackgroundWorkCostStatics(std::nullptr_t = nullptr) noexcept {}
        IBackgroundWorkCostStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBluetoothLEAdvertisementPublisherTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBluetoothLEAdvertisementPublisherTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementPublisherTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IBluetoothLEAdvertisementPublisherTrigger(std::nullptr_t = nullptr) noexcept {}
        IBluetoothLEAdvertisementPublisherTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBluetoothLEAdvertisementPublisherTrigger2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBluetoothLEAdvertisementPublisherTrigger2>
    {
        IBluetoothLEAdvertisementPublisherTrigger2(std::nullptr_t = nullptr) noexcept {}
        IBluetoothLEAdvertisementPublisherTrigger2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBluetoothLEAdvertisementWatcherTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBluetoothLEAdvertisementWatcherTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IBluetoothLEAdvertisementWatcherTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IBluetoothLEAdvertisementWatcherTrigger(std::nullptr_t = nullptr) noexcept {}
        IBluetoothLEAdvertisementWatcherTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBluetoothLEAdvertisementWatcherTrigger2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBluetoothLEAdvertisementWatcherTrigger2>
    {
        IBluetoothLEAdvertisementWatcherTrigger2(std::nullptr_t = nullptr) noexcept {}
        IBluetoothLEAdvertisementWatcherTrigger2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICachedFileUpdaterTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICachedFileUpdaterTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ICachedFileUpdaterTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ICachedFileUpdaterTrigger(std::nullptr_t = nullptr) noexcept {}
        ICachedFileUpdaterTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICachedFileUpdaterTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICachedFileUpdaterTriggerDetails>
    {
        ICachedFileUpdaterTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        ICachedFileUpdaterTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IChatMessageNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IChatMessageNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IChatMessageNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IChatMessageNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IChatMessageNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IChatMessageReceivedNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IChatMessageReceivedNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IChatMessageReceivedNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IChatMessageReceivedNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IChatMessageReceivedNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICommunicationBlockingAppSetAsActiveTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICommunicationBlockingAppSetAsActiveTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ICommunicationBlockingAppSetAsActiveTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ICommunicationBlockingAppSetAsActiveTrigger(std::nullptr_t = nullptr) noexcept {}
        ICommunicationBlockingAppSetAsActiveTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactStoreNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactStoreNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IContactStoreNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IContactStoreNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IContactStoreNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContentPrefetchTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentPrefetchTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IContentPrefetchTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IContentPrefetchTrigger(std::nullptr_t = nullptr) noexcept {}
        IContentPrefetchTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContentPrefetchTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContentPrefetchTriggerFactory>
    {
        IContentPrefetchTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IContentPrefetchTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSystemEventTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSystemEventTrigger>
    {
        ICustomSystemEventTrigger(std::nullptr_t = nullptr) noexcept {}
        ICustomSystemEventTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomSystemEventTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomSystemEventTriggerFactory>
    {
        ICustomSystemEventTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ICustomSystemEventTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceConnectionChangeTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceConnectionChangeTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IDeviceConnectionChangeTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IDeviceConnectionChangeTrigger(std::nullptr_t = nullptr) noexcept {}
        IDeviceConnectionChangeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceConnectionChangeTriggerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceConnectionChangeTriggerStatics>
    {
        IDeviceConnectionChangeTriggerStatics(std::nullptr_t = nullptr) noexcept {}
        IDeviceConnectionChangeTriggerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceManufacturerNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceManufacturerNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IDeviceManufacturerNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IDeviceManufacturerNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IDeviceManufacturerNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceManufacturerNotificationTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceManufacturerNotificationTriggerFactory>
    {
        IDeviceManufacturerNotificationTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IDeviceManufacturerNotificationTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceServicingTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceServicingTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IDeviceServicingTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IDeviceServicingTrigger(std::nullptr_t = nullptr) noexcept {}
        IDeviceServicingTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceUseTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceUseTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IDeviceUseTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IDeviceUseTrigger(std::nullptr_t = nullptr) noexcept {}
        IDeviceUseTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeviceWatcherTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeviceWatcherTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IDeviceWatcherTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IDeviceWatcherTrigger(std::nullptr_t = nullptr) noexcept {}
        IDeviceWatcherTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailStoreNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailStoreNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IEmailStoreNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IEmailStoreNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IEmailStoreNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattCharacteristicNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattCharacteristicNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IGattCharacteristicNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IGattCharacteristicNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        IGattCharacteristicNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattCharacteristicNotificationTrigger2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattCharacteristicNotificationTrigger2>
    {
        IGattCharacteristicNotificationTrigger2(std::nullptr_t = nullptr) noexcept {}
        IGattCharacteristicNotificationTrigger2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattCharacteristicNotificationTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattCharacteristicNotificationTriggerFactory>
    {
        IGattCharacteristicNotificationTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IGattCharacteristicNotificationTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattCharacteristicNotificationTriggerFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattCharacteristicNotificationTriggerFactory2>
    {
        IGattCharacteristicNotificationTriggerFactory2(std::nullptr_t = nullptr) noexcept {}
        IGattCharacteristicNotificationTriggerFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattServiceProviderTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattServiceProviderTrigger>
    {
        IGattServiceProviderTrigger(std::nullptr_t = nullptr) noexcept {}
        IGattServiceProviderTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattServiceProviderTriggerResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattServiceProviderTriggerResult>
    {
        IGattServiceProviderTriggerResult(std::nullptr_t = nullptr) noexcept {}
        IGattServiceProviderTriggerResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGattServiceProviderTriggerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGattServiceProviderTriggerStatics>
    {
        IGattServiceProviderTriggerStatics(std::nullptr_t = nullptr) noexcept {}
        IGattServiceProviderTriggerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGeovisitTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeovisitTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IGeovisitTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IGeovisitTrigger(std::nullptr_t = nullptr) noexcept {}
        IGeovisitTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILocationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILocationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ILocationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ILocationTrigger(std::nullptr_t = nullptr) noexcept {}
        ILocationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILocationTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILocationTriggerFactory>
    {
        ILocationTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ILocationTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMaintenanceTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMaintenanceTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IMaintenanceTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IMaintenanceTrigger(std::nullptr_t = nullptr) noexcept {}
        IMaintenanceTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMaintenanceTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMaintenanceTriggerFactory>
    {
        IMaintenanceTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IMaintenanceTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMediaProcessingTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMediaProcessingTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IMediaProcessingTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IMediaProcessingTrigger(std::nullptr_t = nullptr) noexcept {}
        IMediaProcessingTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkOperatorHotspotAuthenticationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkOperatorHotspotAuthenticationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::INetworkOperatorHotspotAuthenticationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        INetworkOperatorHotspotAuthenticationTrigger(std::nullptr_t = nullptr) noexcept {}
        INetworkOperatorHotspotAuthenticationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkOperatorNotificationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkOperatorNotificationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::INetworkOperatorNotificationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        INetworkOperatorNotificationTrigger(std::nullptr_t = nullptr) noexcept {}
        INetworkOperatorNotificationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INetworkOperatorNotificationTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INetworkOperatorNotificationTriggerFactory>
    {
        INetworkOperatorNotificationTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        INetworkOperatorNotificationTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IPhoneTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IPhoneTrigger(std::nullptr_t = nullptr) noexcept {}
        IPhoneTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneTriggerFactory>
    {
        IPhoneTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IPhoneTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPushNotificationTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPushNotificationTriggerFactory>
    {
        IPushNotificationTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IPushNotificationTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRcsEndUserMessageAvailableTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRcsEndUserMessageAvailableTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IRcsEndUserMessageAvailableTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IRcsEndUserMessageAvailableTrigger(std::nullptr_t = nullptr) noexcept {}
        IRcsEndUserMessageAvailableTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRfcommConnectionTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRfcommConnectionTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IRfcommConnectionTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IRfcommConnectionTrigger(std::nullptr_t = nullptr) noexcept {}
        IRfcommConnectionTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorAuthenticationTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorAuthenticationTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ISecondaryAuthenticationFactorAuthenticationTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ISecondaryAuthenticationFactorAuthenticationTrigger(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorAuthenticationTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISensorDataThresholdTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISensorDataThresholdTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ISensorDataThresholdTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ISensorDataThresholdTrigger(std::nullptr_t = nullptr) noexcept {}
        ISensorDataThresholdTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISensorDataThresholdTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISensorDataThresholdTriggerFactory>
    {
        ISensorDataThresholdTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ISensorDataThresholdTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ISmartCardTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ISmartCardTrigger(std::nullptr_t = nullptr) noexcept {}
        ISmartCardTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardTriggerFactory>
    {
        ISmartCardTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ISmartCardTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmsMessageReceivedTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmsMessageReceivedTriggerFactory>
    {
        ISmsMessageReceivedTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ISmsMessageReceivedTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISocketActivityTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISocketActivityTrigger>
    {
        ISocketActivityTrigger(std::nullptr_t = nullptr) noexcept {}
        ISocketActivityTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageLibraryChangeTrackerTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageLibraryChangeTrackerTriggerFactory>
    {
        IStorageLibraryChangeTrackerTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IStorageLibraryChangeTrackerTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageLibraryContentChangedTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageLibraryContentChangedTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::IStorageLibraryContentChangedTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        IStorageLibraryContentChangedTrigger(std::nullptr_t = nullptr) noexcept {}
        IStorageLibraryContentChangedTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageLibraryContentChangedTriggerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageLibraryContentChangedTriggerStatics>
    {
        IStorageLibraryContentChangedTriggerStatics(std::nullptr_t = nullptr) noexcept {}
        IStorageLibraryContentChangedTriggerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemCondition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemCondition>,
        impl::require<winrt::Windows::ApplicationModel::Background::ISystemCondition, winrt::Windows::ApplicationModel::Background::IBackgroundCondition>
    {
        ISystemCondition(std::nullptr_t = nullptr) noexcept {}
        ISystemCondition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemConditionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemConditionFactory>
    {
        ISystemConditionFactory(std::nullptr_t = nullptr) noexcept {}
        ISystemConditionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ISystemTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ISystemTrigger(std::nullptr_t = nullptr) noexcept {}
        ISystemTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemTriggerFactory>
    {
        ISystemTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ISystemTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITimeTrigger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITimeTrigger>,
        impl::require<winrt::Windows::ApplicationModel::Background::ITimeTrigger, winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>
    {
        ITimeTrigger(std::nullptr_t = nullptr) noexcept {}
        ITimeTrigger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITimeTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITimeTriggerFactory>
    {
        ITimeTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        ITimeTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IToastNotificationActionTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IToastNotificationActionTriggerFactory>
    {
        IToastNotificationActionTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IToastNotificationActionTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IToastNotificationHistoryChangedTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IToastNotificationHistoryChangedTriggerFactory>
    {
        IToastNotificationHistoryChangedTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IToastNotificationHistoryChangedTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserNotificationChangedTriggerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserNotificationChangedTriggerFactory>
    {
        IUserNotificationChangedTriggerFactory(std::nullptr_t = nullptr) noexcept {}
        IUserNotificationChangedTriggerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
