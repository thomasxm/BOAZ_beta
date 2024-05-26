// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Activation_2_H
#define WINRT_Windows_ApplicationModel_Activation_2_H
#include "winrt/impl/Windows.ApplicationModel.Activation.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation
{
    struct __declspec(empty_bases) AppointmentsProviderAddAppointmentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderAddAppointmentActivatedEventArgs,
        impl::require<AppointmentsProviderAddAppointmentActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        AppointmentsProviderAddAppointmentActivatedEventArgs(std::nullptr_t) noexcept {}
        AppointmentsProviderAddAppointmentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderAddAppointmentActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppointmentsProviderRemoveAppointmentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderRemoveAppointmentActivatedEventArgs,
        impl::require<AppointmentsProviderRemoveAppointmentActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        AppointmentsProviderRemoveAppointmentActivatedEventArgs(std::nullptr_t) noexcept {}
        AppointmentsProviderRemoveAppointmentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderRemoveAppointmentActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppointmentsProviderReplaceAppointmentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderReplaceAppointmentActivatedEventArgs,
        impl::require<AppointmentsProviderReplaceAppointmentActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        AppointmentsProviderReplaceAppointmentActivatedEventArgs(std::nullptr_t) noexcept {}
        AppointmentsProviderReplaceAppointmentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderReplaceAppointmentActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppointmentsProviderShowAppointmentDetailsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowAppointmentDetailsActivatedEventArgs,
        impl::require<AppointmentsProviderShowAppointmentDetailsActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        AppointmentsProviderShowAppointmentDetailsActivatedEventArgs(std::nullptr_t) noexcept {}
        AppointmentsProviderShowAppointmentDetailsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowAppointmentDetailsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppointmentsProviderShowTimeFrameActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowTimeFrameActivatedEventArgs,
        impl::require<AppointmentsProviderShowTimeFrameActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        AppointmentsProviderShowTimeFrameActivatedEventArgs(std::nullptr_t) noexcept {}
        AppointmentsProviderShowTimeFrameActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowTimeFrameActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BackgroundActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs
    {
        BackgroundActivatedEventArgs(std::nullptr_t) noexcept {}
        BackgroundActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BarcodeScannerPreviewActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IBarcodeScannerPreviewActivatedEventArgs,
        impl::require<BarcodeScannerPreviewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        BarcodeScannerPreviewActivatedEventArgs(std::nullptr_t) noexcept {}
        BarcodeScannerPreviewActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IBarcodeScannerPreviewActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CachedFileUpdaterActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ICachedFileUpdaterActivatedEventArgs,
        impl::require<CachedFileUpdaterActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        CachedFileUpdaterActivatedEventArgs(std::nullptr_t) noexcept {}
        CachedFileUpdaterActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICachedFileUpdaterActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CameraSettingsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ICameraSettingsActivatedEventArgs
    {
        CameraSettingsActivatedEventArgs(std::nullptr_t) noexcept {}
        CameraSettingsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICameraSettingsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CommandLineActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ICommandLineActivatedEventArgs,
        impl::require<CommandLineActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        CommandLineActivatedEventArgs(std::nullptr_t) noexcept {}
        CommandLineActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICommandLineActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CommandLineActivationOperation : winrt::Windows::ApplicationModel::Activation::ICommandLineActivationOperation
    {
        CommandLineActivationOperation(std::nullptr_t) noexcept {}
        CommandLineActivationOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICommandLineActivationOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactCallActivatedEventArgs
    {
        ContactCallActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactMapActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactMapActivatedEventArgs
    {
        ContactMapActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactMapActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactMapActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactMessageActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactMessageActivatedEventArgs
    {
        ContactMessageActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactMessageActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactMessageActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactPanelActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactPanelActivatedEventArgs,
        impl::require<ContactPanelActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        ContactPanelActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactPanelActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactPanelActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactPickerActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactPickerActivatedEventArgs
    {
        ContactPickerActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactPickerActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactPickerActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactPostActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactPostActivatedEventArgs
    {
        ContactPostActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactPostActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactPostActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ContactVideoCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactVideoCallActivatedEventArgs
    {
        ContactVideoCallActivatedEventArgs(std::nullptr_t) noexcept {}
        ContactVideoCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactVideoCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DeviceActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IDeviceActivatedEventArgs,
        impl::require<DeviceActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        DeviceActivatedEventArgs(std::nullptr_t) noexcept {}
        DeviceActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IDeviceActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DevicePairingActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IDevicePairingActivatedEventArgs,
        impl::require<DevicePairingActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        DevicePairingActivatedEventArgs(std::nullptr_t) noexcept {}
        DevicePairingActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IDevicePairingActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DialReceiverActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IDialReceiverActivatedEventArgs,
        impl::require<DialReceiverActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        DialReceiverActivatedEventArgs(std::nullptr_t) noexcept {}
        DialReceiverActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IDialReceiverActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FileActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgs,
        impl::require<FileActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgsWithNeighboringFiles, winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgsWithCallerPackageFamilyName, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        FileActivatedEventArgs(std::nullptr_t) noexcept {}
        FileActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FileOpenPickerActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs,
        impl::require<FileOpenPickerActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs2, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        FileOpenPickerActivatedEventArgs(std::nullptr_t) noexcept {}
        FileOpenPickerActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FileOpenPickerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerContinuationEventArgs,
        impl::require<FileOpenPickerContinuationEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        FileOpenPickerContinuationEventArgs(std::nullptr_t) noexcept {}
        FileOpenPickerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FileSavePickerActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs,
        impl::require<FileSavePickerActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs2, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        FileSavePickerActivatedEventArgs(std::nullptr_t) noexcept {}
        FileSavePickerActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FileSavePickerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IFileSavePickerContinuationEventArgs,
        impl::require<FileSavePickerContinuationEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        FileSavePickerContinuationEventArgs(std::nullptr_t) noexcept {}
        FileSavePickerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileSavePickerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FolderPickerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IFolderPickerContinuationEventArgs,
        impl::require<FolderPickerContinuationEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        FolderPickerContinuationEventArgs(std::nullptr_t) noexcept {}
        FolderPickerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFolderPickerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LaunchActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs,
        impl::require<LaunchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IPrelaunchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs2, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        LaunchActivatedEventArgs(std::nullptr_t) noexcept {}
        LaunchActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LockScreenActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ILockScreenActivatedEventArgs,
        impl::require<LockScreenActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        LockScreenActivatedEventArgs(std::nullptr_t) noexcept {}
        LockScreenActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ILockScreenActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LockScreenCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ILockScreenCallActivatedEventArgs,
        impl::require<LockScreenCallActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider>
    {
        LockScreenCallActivatedEventArgs(std::nullptr_t) noexcept {}
        LockScreenCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ILockScreenCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LockScreenComponentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs
    {
        LockScreenComponentActivatedEventArgs(std::nullptr_t) noexcept {}
        LockScreenComponentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPhoneCallActivatedEventArgs,
        impl::require<PhoneCallActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        PhoneCallActivatedEventArgs(std::nullptr_t) noexcept {}
        PhoneCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPhoneCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PickerReturnedActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPickerReturnedActivatedEventArgs
    {
        PickerReturnedActivatedEventArgs(std::nullptr_t) noexcept {}
        PickerReturnedActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPickerReturnedActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) Print3DWorkflowActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPrint3DWorkflowActivatedEventArgs
    {
        Print3DWorkflowActivatedEventArgs(std::nullptr_t) noexcept {}
        Print3DWorkflowActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPrint3DWorkflowActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTaskSettingsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPrintTaskSettingsActivatedEventArgs
    {
        PrintTaskSettingsActivatedEventArgs(std::nullptr_t) noexcept {}
        PrintTaskSettingsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPrintTaskSettingsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProtocolActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs,
        impl::require<ProtocolActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgsWithCallerPackageFamilyNameAndData, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        ProtocolActivatedEventArgs(std::nullptr_t) noexcept {}
        ProtocolActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProtocolForResultsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IProtocolForResultsActivatedEventArgs,
        impl::require<ProtocolForResultsActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgsWithCallerPackageFamilyNameAndData, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        ProtocolForResultsActivatedEventArgs(std::nullptr_t) noexcept {}
        ProtocolForResultsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IProtocolForResultsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RestrictedLaunchActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IRestrictedLaunchActivatedEventArgs,
        impl::require<RestrictedLaunchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        RestrictedLaunchActivatedEventArgs(std::nullptr_t) noexcept {}
        RestrictedLaunchActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IRestrictedLaunchActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SearchActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ISearchActivatedEventArgs,
        impl::require<SearchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::ISearchActivatedEventArgsWithLinguisticDetails, winrt::Windows::ApplicationModel::Activation::IViewSwitcherProvider, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        SearchActivatedEventArgs(std::nullptr_t) noexcept {}
        SearchActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ISearchActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareTargetActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IShareTargetActivatedEventArgs,
        impl::require<ShareTargetActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        ShareTargetActivatedEventArgs(std::nullptr_t) noexcept {}
        ShareTargetActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IShareTargetActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SplashScreen : winrt::Windows::ApplicationModel::Activation::ISplashScreen
    {
        SplashScreen(std::nullptr_t) noexcept {}
        SplashScreen(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ISplashScreen(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) StartupTaskActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IStartupTaskActivatedEventArgs,
        impl::require<StartupTaskActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        StartupTaskActivatedEventArgs(std::nullptr_t) noexcept {}
        StartupTaskActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IStartupTaskActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) TileActivatedInfo : winrt::Windows::ApplicationModel::Activation::ITileActivatedInfo
    {
        TileActivatedInfo(std::nullptr_t) noexcept {}
        TileActivatedInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ITileActivatedInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ToastNotificationActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IToastNotificationActivatedEventArgs,
        impl::require<ToastNotificationActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs>
    {
        ToastNotificationActivatedEventArgs(std::nullptr_t) noexcept {}
        ToastNotificationActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IToastNotificationActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataAccountProviderActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IUserDataAccountProviderActivatedEventArgs
    {
        UserDataAccountProviderActivatedEventArgs(std::nullptr_t) noexcept {}
        UserDataAccountProviderActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IUserDataAccountProviderActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VoiceCommandActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IVoiceCommandActivatedEventArgs,
        impl::require<VoiceCommandActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        VoiceCommandActivatedEventArgs(std::nullptr_t) noexcept {}
        VoiceCommandActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IVoiceCommandActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WalletActionActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IWalletActionActivatedEventArgs
    {
        WalletActionActivatedEventArgs(std::nullptr_t) noexcept {}
        WalletActionActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IWalletActionActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebAccountProviderActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IWebAccountProviderActivatedEventArgs,
        impl::require<WebAccountProviderActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebAccountProviderActivatedEventArgs(std::nullptr_t) noexcept {}
        WebAccountProviderActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IWebAccountProviderActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebAuthenticationBrokerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IWebAuthenticationBrokerContinuationEventArgs
    {
        WebAuthenticationBrokerContinuationEventArgs(std::nullptr_t) noexcept {}
        WebAuthenticationBrokerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IWebAuthenticationBrokerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
