// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_AllJoyn_0_H
#define WINRT_Windows_Devices_AllJoyn_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration
{
    struct DeviceWatcher;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct Deferral;
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename K, typename V> struct __declspec(empty_bases) IMap;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Globalization
{
    struct Language;
}
WINRT_EXPORT namespace winrt::Windows::Networking::Sockets
{
    enum class SocketSslErrorSeverity : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Security::Credentials
{
    struct PasswordCredential;
}
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Certificates
{
    struct Certificate;
    enum class ChainValidationResult : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Devices::AllJoyn
{
    enum class AllJoynAuthenticationMechanism : int32_t
    {
        None = 0,
        SrpAnonymous = 1,
        SrpLogon = 2,
        EcdheNull = 3,
        EcdhePsk = 4,
        EcdheEcdsa = 5,
        EcdheSpeke = 6,
    };
    enum class AllJoynBusAttachmentState : int32_t
    {
        Disconnected = 0,
        Connecting = 1,
        Connected = 2,
        Disconnecting = 3,
    };
    enum class AllJoynSessionLostReason : int32_t
    {
        None = 0,
        ProducerLeftSession = 1,
        ProducerClosedAbruptly = 2,
        RemovedByProducer = 3,
        LinkTimeout = 4,
        Other = 5,
    };
    enum class AllJoynTrafficType : int32_t
    {
        Unknown = 0,
        Messages = 1,
        RawUnreliable = 2,
        RawReliable = 4,
    };
    struct IAllJoynAboutData;
    struct IAllJoynAboutDataView;
    struct IAllJoynAboutDataViewStatics;
    struct IAllJoynAcceptSessionJoiner;
    struct IAllJoynAcceptSessionJoinerEventArgs;
    struct IAllJoynAcceptSessionJoinerEventArgsFactory;
    struct IAllJoynAuthenticationCompleteEventArgs;
    struct IAllJoynBusAttachment;
    struct IAllJoynBusAttachment2;
    struct IAllJoynBusAttachmentFactory;
    struct IAllJoynBusAttachmentStateChangedEventArgs;
    struct IAllJoynBusAttachmentStatics;
    struct IAllJoynBusObject;
    struct IAllJoynBusObjectFactory;
    struct IAllJoynBusObjectStoppedEventArgs;
    struct IAllJoynBusObjectStoppedEventArgsFactory;
    struct IAllJoynCredentials;
    struct IAllJoynCredentialsRequestedEventArgs;
    struct IAllJoynCredentialsVerificationRequestedEventArgs;
    struct IAllJoynMessageInfo;
    struct IAllJoynMessageInfoFactory;
    struct IAllJoynProducer;
    struct IAllJoynProducerStoppedEventArgs;
    struct IAllJoynProducerStoppedEventArgsFactory;
    struct IAllJoynServiceInfo;
    struct IAllJoynServiceInfoFactory;
    struct IAllJoynServiceInfoRemovedEventArgs;
    struct IAllJoynServiceInfoRemovedEventArgsFactory;
    struct IAllJoynServiceInfoStatics;
    struct IAllJoynSession;
    struct IAllJoynSessionJoinedEventArgs;
    struct IAllJoynSessionJoinedEventArgsFactory;
    struct IAllJoynSessionLostEventArgs;
    struct IAllJoynSessionLostEventArgsFactory;
    struct IAllJoynSessionMemberAddedEventArgs;
    struct IAllJoynSessionMemberAddedEventArgsFactory;
    struct IAllJoynSessionMemberRemovedEventArgs;
    struct IAllJoynSessionMemberRemovedEventArgsFactory;
    struct IAllJoynSessionStatics;
    struct IAllJoynStatusStatics;
    struct IAllJoynWatcherStoppedEventArgs;
    struct IAllJoynWatcherStoppedEventArgsFactory;
    struct AllJoynAboutData;
    struct AllJoynAboutDataView;
    struct AllJoynAcceptSessionJoinerEventArgs;
    struct AllJoynAuthenticationCompleteEventArgs;
    struct AllJoynBusAttachment;
    struct AllJoynBusAttachmentStateChangedEventArgs;
    struct AllJoynBusObject;
    struct AllJoynBusObjectStoppedEventArgs;
    struct AllJoynCredentials;
    struct AllJoynCredentialsRequestedEventArgs;
    struct AllJoynCredentialsVerificationRequestedEventArgs;
    struct AllJoynMessageInfo;
    struct AllJoynProducerStoppedEventArgs;
    struct AllJoynServiceInfo;
    struct AllJoynServiceInfoRemovedEventArgs;
    struct AllJoynSession;
    struct AllJoynSessionJoinedEventArgs;
    struct AllJoynSessionLostEventArgs;
    struct AllJoynSessionMemberAddedEventArgs;
    struct AllJoynSessionMemberRemovedEventArgs;
    struct AllJoynStatus;
    struct AllJoynWatcherStoppedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynProducer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynAboutData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynBusObject>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynCredentials>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynMessageInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynStatus>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::AllJoyn::AllJoynTrafficType>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynAboutData> = L"Windows.Devices.AllJoyn.AllJoynAboutData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView> = L"Windows.Devices.AllJoyn.AllJoynAboutDataView";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> = L"Windows.Devices.AllJoyn.AllJoynAcceptSessionJoinerEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> = L"Windows.Devices.AllJoyn.AllJoynAuthenticationCompleteEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment> = L"Windows.Devices.AllJoyn.AllJoynBusAttachment";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynBusAttachmentStateChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynBusObject> = L"Windows.Devices.AllJoyn.AllJoynBusObject";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynBusObjectStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynCredentials> = L"Windows.Devices.AllJoyn.AllJoynCredentials";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynCredentialsRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynCredentialsVerificationRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynMessageInfo> = L"Windows.Devices.AllJoyn.AllJoynMessageInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynProducerStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo> = L"Windows.Devices.AllJoyn.AllJoynServiceInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynServiceInfoRemovedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynSession> = L"Windows.Devices.AllJoyn.AllJoynSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynSessionJoinedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> = L"Windows.Devices.AllJoyn.AllJoynSessionLostEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynSessionMemberAddedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynSessionMemberRemovedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynStatus> = L"Windows.Devices.AllJoyn.AllJoynStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs> = L"Windows.Devices.AllJoyn.AllJoynWatcherStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism> = L"Windows.Devices.AllJoyn.AllJoynAuthenticationMechanism";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentState> = L"Windows.Devices.AllJoyn.AllJoynBusAttachmentState";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostReason> = L"Windows.Devices.AllJoyn.AllJoynSessionLostReason";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::AllJoynTrafficType> = L"Windows.Devices.AllJoyn.AllJoynTrafficType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData> = L"Windows.Devices.AllJoyn.IAllJoynAboutData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView> = L"Windows.Devices.AllJoyn.IAllJoynAboutDataView";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics> = L"Windows.Devices.AllJoyn.IAllJoynAboutDataViewStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner> = L"Windows.Devices.AllJoyn.IAllJoynAcceptSessionJoiner";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynAcceptSessionJoinerEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynAcceptSessionJoinerEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynAuthenticationCompleteEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment> = L"Windows.Devices.AllJoyn.IAllJoynBusAttachment";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2> = L"Windows.Devices.AllJoyn.IAllJoynBusAttachment2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory> = L"Windows.Devices.AllJoyn.IAllJoynBusAttachmentFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynBusAttachmentStateChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics> = L"Windows.Devices.AllJoyn.IAllJoynBusAttachmentStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject> = L"Windows.Devices.AllJoyn.IAllJoynBusObject";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory> = L"Windows.Devices.AllJoyn.IAllJoynBusObjectFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynBusObjectStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynBusObjectStoppedEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials> = L"Windows.Devices.AllJoyn.IAllJoynCredentials";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynCredentialsRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynCredentialsVerificationRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo> = L"Windows.Devices.AllJoyn.IAllJoynMessageInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory> = L"Windows.Devices.AllJoyn.IAllJoynMessageInfoFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynProducer> = L"Windows.Devices.AllJoyn.IAllJoynProducer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynProducerStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynProducerStoppedEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo> = L"Windows.Devices.AllJoyn.IAllJoynServiceInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory> = L"Windows.Devices.AllJoyn.IAllJoynServiceInfoFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynServiceInfoRemovedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynServiceInfoRemovedEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics> = L"Windows.Devices.AllJoyn.IAllJoynServiceInfoStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSession> = L"Windows.Devices.AllJoyn.IAllJoynSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynSessionJoinedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynSessionJoinedEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynSessionLostEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynSessionLostEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynSessionMemberAddedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynSessionMemberAddedEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynSessionMemberRemovedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynSessionMemberRemovedEventArgsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics> = L"Windows.Devices.AllJoyn.IAllJoynSessionStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics> = L"Windows.Devices.AllJoyn.IAllJoynStatusStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs> = L"Windows.Devices.AllJoyn.IAllJoynWatcherStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory> = L"Windows.Devices.AllJoyn.IAllJoynWatcherStoppedEventArgsFactory";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData>{ 0xE5A9BF00,0x1FA2,0x4839,{ 0x93,0xEF,0xF9,0xDF,0x40,0x48,0x90,0xF7 } }; // E5A9BF00-1FA2-4839-93EF-F9DF404890F7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView>{ 0x6823111F,0x6212,0x4934,{ 0x9C,0x48,0xE1,0x9C,0xA4,0x98,0x42,0x88 } }; // 6823111F-6212-4934-9C48-E19CA4984288
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>{ 0x57EDB688,0x0C5E,0x416E,{ 0x88,0xB5,0x39,0xB3,0x2D,0x25,0xC4,0x7D } }; // 57EDB688-0C5E-416E-88B5-39B32D25C47D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner>{ 0x4DA817D2,0xCD1D,0x4023,{ 0xA7,0xC4,0x16,0xDE,0xF8,0x9C,0x28,0xDF } }; // 4DA817D2-CD1D-4023-A7C4-16DEF89C28DF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs>{ 0x4EFB5365,0x3E8A,0x4257,{ 0x8F,0x10,0x53,0x9C,0xE0,0xD5,0x6C,0x0F } }; // 4EFB5365-3E8A-4257-8F10-539CE0D56C0F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory>{ 0xB4435BC0,0x6145,0x429E,{ 0x84,0xDB,0xD5,0xBF,0xE7,0x72,0xB1,0x4F } }; // B4435BC0-6145-429E-84DB-D5BFE772B14F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs>{ 0x97B4701C,0x15DC,0x4B53,{ 0xB6,0xA4,0x7D,0x13,0x43,0x00,0xD7,0xBF } }; // 97B4701C-15DC-4B53-B6A4-7D134300D7BF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>{ 0xF309F153,0x1EED,0x42C3,{ 0xA2,0x0E,0x43,0x6D,0x41,0xFE,0x62,0xF6 } }; // F309F153-1EED-42C3-A20E-436D41FE62F6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2>{ 0x3474CB1E,0x2368,0x43B2,{ 0xB4,0x3E,0x6A,0x3A,0xC1,0x27,0x8D,0x98 } }; // 3474CB1E-2368-43B2-B43E-6A3AC1278D98
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory>{ 0x642EF1A4,0xAD85,0x4DDF,{ 0x90,0xAE,0x60,0x44,0x52,0xB2,0x22,0x88 } }; // 642EF1A4-AD85-4DDF-90AE-604452B22288
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs>{ 0xD82E75F4,0xC02A,0x41EC,{ 0xA8,0xD5,0xEA,0xB1,0x55,0x89,0x53,0xAA } }; // D82E75F4-C02A-41EC-A8D5-EAB1558953AA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>{ 0x839D4D3D,0x1051,0x40D7,{ 0x87,0x2A,0x8D,0x01,0x41,0x11,0x5B,0x1F } }; // 839D4D3D-1051-40D7-872A-8D0141115B1F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject>{ 0xE8FD825E,0xF73A,0x490C,{ 0x88,0x04,0x04,0xE0,0x26,0x64,0x30,0x47 } }; // E8FD825E-F73A-490C-8804-04E026643047
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>{ 0x2C2F9F0B,0x8E02,0x4F9C,{ 0xAC,0x27,0xEA,0x6D,0xAD,0x5D,0x3B,0x50 } }; // 2C2F9F0B-8E02-4F9C-AC27-EA6DAD5D3B50
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs>{ 0xDE102115,0xEF8E,0x4D42,{ 0xB9,0x3B,0xA2,0xAE,0x74,0x51,0x97,0x66 } }; // DE102115-EF8E-4D42-B93B-A2AE74519766
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory>{ 0x6B22FD48,0xD0A3,0x4255,{ 0x95,0x3A,0x47,0x72,0xB4,0x02,0x80,0x73 } }; // 6B22FD48-D0A3-4255-953A-4772B4028073
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials>{ 0x824650F2,0xA190,0x40B1,{ 0xAB,0xAB,0x34,0x9E,0xC2,0x44,0xDF,0xAA } }; // 824650F2-A190-40B1-ABAB-349EC244DFAA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs>{ 0x6A87E34E,0xB069,0x4B80,{ 0x9E,0x1A,0x41,0xBC,0x83,0x7C,0x65,0xD2 } }; // 6A87E34E-B069-4B80-9E1A-41BC837C65D2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs>{ 0x800A7612,0xB805,0x44AF,{ 0xA2,0xE1,0x79,0x2A,0xB6,0x55,0xA2,0xD0 } }; // 800A7612-B805-44AF-A2E1-792AB655A2D0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo>{ 0xFF2B0127,0x2C12,0x4859,{ 0xAA,0x3A,0xC7,0x44,0x61,0xEE,0x81,0x4C } }; // FF2B0127-2C12-4859-AA3A-C74461EE814C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory>{ 0x34664C2A,0x8289,0x43D4,{ 0xB4,0xA8,0x3F,0x4D,0xE3,0x59,0xF0,0x43 } }; // 34664C2A-8289-43D4-B4A8-3F4DE359F043
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynProducer>{ 0x9D084679,0x469B,0x495A,{ 0xA7,0x10,0xAC,0x50,0xF1,0x23,0x06,0x9F } }; // 9D084679-469B-495A-A710-AC50F123069F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs>{ 0x51309770,0x4937,0x492D,{ 0x80,0x80,0x23,0x64,0x39,0x98,0x7C,0xEB } }; // 51309770-4937-492D-8080-236439987CEB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory>{ 0x56529961,0xB219,0x4D6E,{ 0x9F,0x78,0xFA,0x3F,0x99,0xFA,0x8F,0xE5 } }; // 56529961-B219-4D6E-9F78-FA3F99FA8FE5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo>{ 0x4CBE8209,0xB93E,0x4182,{ 0x99,0x9B,0xDD,0xD0,0x00,0xF9,0xC5,0x75 } }; // 4CBE8209-B93E-4182-999B-DDD000F9C575
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory>{ 0x7581DABD,0xFE03,0x4F4B,{ 0x94,0xA4,0xF0,0x2F,0xDC,0xBD,0x11,0xB8 } }; // 7581DABD-FE03-4F4B-94A4-F02FDCBD11B8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs>{ 0x3057A95F,0x1D3F,0x41F3,{ 0x89,0x69,0xE3,0x27,0x92,0x62,0x73,0x96 } }; // 3057A95F-1D3F-41F3-8969-E32792627396
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory>{ 0x0DBF8627,0x9AFF,0x4955,{ 0x92,0x27,0x69,0x53,0xBA,0xF4,0x15,0x69 } }; // 0DBF8627-9AFF-4955-9227-6953BAF41569
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics>{ 0x5678570A,0x603A,0x49FC,{ 0xB7,0x50,0x0E,0xF1,0x36,0x09,0x21,0x3C } }; // 5678570A-603A-49FC-B750-0EF13609213C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSession>{ 0xE8D11B0C,0xC0D4,0x406C,{ 0x88,0xA9,0xA9,0x3E,0xFA,0x85,0xD4,0xB1 } }; // E8D11B0C-C0D4-406C-88A9-A93EFA85D4B1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs>{ 0x9E9F5BD0,0xB5D7,0x47C5,{ 0x8D,0xAB,0xB0,0x40,0xCC,0x19,0x28,0x71 } }; // 9E9F5BD0-B5D7-47C5-8DAB-B040CC192871
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory>{ 0x6824D689,0xD6CB,0x4D9E,{ 0xA0,0x9E,0x35,0x80,0x68,0x70,0xB1,0x7F } }; // 6824D689-D6CB-4D9E-A09E-35806870B17F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs>{ 0xE766A48A,0x8BB8,0x4954,{ 0xAE,0x67,0xD2,0xFA,0x43,0xD1,0xF9,0x6B } }; // E766A48A-8BB8-4954-AE67-D2FA43D1F96B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory>{ 0x13BBFD32,0xD2F4,0x49C9,{ 0x98,0x0E,0x28,0x05,0xE1,0x35,0x86,0xB1 } }; // 13BBFD32-D2F4-49C9-980E-2805E13586B1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs>{ 0x49A2798A,0x0DD1,0x46C1,{ 0x9C,0xD6,0x27,0x19,0x0E,0x50,0x3A,0x5E } }; // 49A2798A-0DD1-46C1-9CD6-27190E503A5E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory>{ 0x341DE352,0x1D33,0x40A1,{ 0xA1,0xD3,0xE5,0x77,0x70,0x20,0xE1,0xF1 } }; // 341DE352-1D33-40A1-A1D3-E5777020E1F1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs>{ 0x409A219F,0xAA4A,0x4893,{ 0xB4,0x30,0xBA,0xA1,0xB6,0x3C,0x62,0x19 } }; // 409A219F-AA4A-4893-B430-BAA1B63C6219
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory>{ 0xC4D355E8,0x42B8,0x4B67,{ 0xB7,0x57,0xD0,0xCF,0xCA,0xD5,0x92,0x80 } }; // C4D355E8-42B8-4B67-B757-D0CFCAD59280
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics>{ 0x9E05D604,0xA06C,0x46D4,{ 0xB4,0x6C,0x0B,0x0B,0x54,0x10,0x5B,0x44 } }; // 9E05D604-A06C-46D4-B46C-0B0B54105B44
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics>{ 0xD0B7A17E,0x0D29,0x4DA9,{ 0x8A,0xC6,0x54,0xC5,0x54,0xBE,0xDB,0xC5 } }; // D0B7A17E-0D29-4DA9-8AC6-54C554BEDBC5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs>{ 0xC9FCA03B,0x701D,0x4AA8,{ 0x97,0xDD,0xA2,0xBB,0x0A,0x8F,0x5F,0xA3 } }; // C9FCA03B-701D-4AA8-97DD-A2BB0A8F5FA3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory>{ 0x878FA5A8,0x2D50,0x47E1,{ 0x90,0x4A,0x20,0xBF,0x0D,0x48,0xC7,0x82 } }; // 878FA5A8-2D50-47E1-904A-20BF0D48C782
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynAboutData>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynAboutData; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynBusObject>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynBusObject; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynCredentials>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynCredentials; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynMessageInfo>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynSession>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynSession; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs>{ using type = winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs; };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_DefaultAppName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DefaultAppName(void*) noexcept = 0;
            virtual int32_t __stdcall get_AppNames(void**) noexcept = 0;
            virtual int32_t __stdcall get_DateOfManufacture(void**) noexcept = 0;
            virtual int32_t __stdcall put_DateOfManufacture(void*) noexcept = 0;
            virtual int32_t __stdcall get_DefaultDescription(void**) noexcept = 0;
            virtual int32_t __stdcall put_DefaultDescription(void*) noexcept = 0;
            virtual int32_t __stdcall get_Descriptions(void**) noexcept = 0;
            virtual int32_t __stdcall get_DefaultManufacturer(void**) noexcept = 0;
            virtual int32_t __stdcall put_DefaultManufacturer(void*) noexcept = 0;
            virtual int32_t __stdcall get_Manufacturers(void**) noexcept = 0;
            virtual int32_t __stdcall get_ModelNumber(void**) noexcept = 0;
            virtual int32_t __stdcall put_ModelNumber(void*) noexcept = 0;
            virtual int32_t __stdcall get_SoftwareVersion(void**) noexcept = 0;
            virtual int32_t __stdcall put_SoftwareVersion(void*) noexcept = 0;
            virtual int32_t __stdcall get_SupportUrl(void**) noexcept = 0;
            virtual int32_t __stdcall put_SupportUrl(void*) noexcept = 0;
            virtual int32_t __stdcall get_AppId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_AppId(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
            virtual int32_t __stdcall get_AJSoftwareVersion(void**) noexcept = 0;
            virtual int32_t __stdcall get_AppId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_DateOfManufacture(void**) noexcept = 0;
            virtual int32_t __stdcall get_DefaultLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_HardwareVersion(void**) noexcept = 0;
            virtual int32_t __stdcall get_ModelNumber(void**) noexcept = 0;
            virtual int32_t __stdcall get_SoftwareVersion(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedLanguages(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportUrl(void**) noexcept = 0;
            virtual int32_t __stdcall get_AppName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Manufacturer(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDataBySessionPortAsync(void*, void*, uint16_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDataBySessionPortWithLanguageAsync(void*, void*, uint16_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Accept() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UniqueName(void**) noexcept = 0;
            virtual int32_t __stdcall get_SessionPort(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_TrafficType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SamePhysicalNode(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SameNetwork(bool*) noexcept = 0;
            virtual int32_t __stdcall Accept() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, uint16_t, int32_t, uint8_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AuthenticationMechanism(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PeerUniqueName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Succeeded(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AboutData(void**) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionSpecification(void**) noexcept = 0;
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UniqueName(void**) noexcept = 0;
            virtual int32_t __stdcall PingAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall Connect() noexcept = 0;
            virtual int32_t __stdcall Disconnect() noexcept = 0;
            virtual int32_t __stdcall add_StateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_AuthenticationMechanisms(void**) noexcept = 0;
            virtual int32_t __stdcall add_CredentialsRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_CredentialsRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_CredentialsVerificationRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_CredentialsVerificationRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AuthenticationComplete(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AuthenticationComplete(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetAboutDataAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetAboutDataWithLanguageAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_AcceptSessionJoinerRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AcceptSessionJoinerRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SessionJoined(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SessionJoined(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall GetWatcher(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall AddProducer(void*) noexcept = 0;
            virtual int32_t __stdcall get_BusAttachment(void**) noexcept = 0;
            virtual int32_t __stdcall get_Session(void**) noexcept = 0;
            virtual int32_t __stdcall add_Stopped(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Stopped(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithBusAttachment(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AuthenticationMechanism(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Certificate(void**) noexcept = 0;
            virtual int32_t __stdcall put_Certificate(void*) noexcept = 0;
            virtual int32_t __stdcall get_PasswordCredential(void**) noexcept = 0;
            virtual int32_t __stdcall put_PasswordCredential(void*) noexcept = 0;
            virtual int32_t __stdcall get_Timeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_Timeout(int64_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AttemptCount(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Credentials(void**) noexcept = 0;
            virtual int32_t __stdcall get_PeerUniqueName(void**) noexcept = 0;
            virtual int32_t __stdcall get_RequestedUserName(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AuthenticationMechanism(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PeerUniqueName(void**) noexcept = 0;
            virtual int32_t __stdcall get_PeerCertificate(void**) noexcept = 0;
            virtual int32_t __stdcall get_PeerCertificateErrorSeverity(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PeerCertificateErrors(void**) noexcept = 0;
            virtual int32_t __stdcall get_PeerIntermediateCertificates(void**) noexcept = 0;
            virtual int32_t __stdcall Accept() noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SenderUniqueName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynProducer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetBusObject(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UniqueName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ObjectPath(void**) noexcept = 0;
            virtual int32_t __stdcall get_SessionPort(uint16_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void*, uint16_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UniqueName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall RemoveMemberAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_MemberAdded(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MemberAdded(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_MemberRemoved(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MemberRemoved(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Lost(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Lost(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Session(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reason(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UniqueName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UniqueName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFromServiceInfoAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetFromServiceInfoAndBusAttachmentAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Ok(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Fail(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_OperationTimedOut(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_OtherEndClosed(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionRefused(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AuthenticationFailed(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AuthenticationRejectedByUser(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SslConnectFailed(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SslIdentityVerificationFailed(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InsufficientSecurity(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument1(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument2(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument3(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument4(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument5(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument6(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument7(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InvalidArgument8(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(int32_t, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAboutData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        WINRT_IMPL_AUTO(void) IsEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DefaultAppName() const;
        WINRT_IMPL_AUTO(void) DefaultAppName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) AppNames() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) DateOfManufacture() const;
        WINRT_IMPL_AUTO(void) DateOfManufacture(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DefaultDescription() const;
        WINRT_IMPL_AUTO(void) DefaultDescription(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) Descriptions() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DefaultManufacturer() const;
        WINRT_IMPL_AUTO(void) DefaultManufacturer(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) Manufacturers() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ModelNumber() const;
        WINRT_IMPL_AUTO(void) ModelNumber(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SoftwareVersion() const;
        WINRT_IMPL_AUTO(void) SoftwareVersion(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) SupportUrl() const;
        WINRT_IMPL_AUTO(void) SupportUrl(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) AppId() const;
        WINRT_IMPL_AUTO(void) AppId(winrt::guid const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AJSoftwareVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) AppId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) DateOfManufacture() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) DefaultLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HardwareVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ModelNumber() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SoftwareVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>) SupportedLanguages() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) SupportUrl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AppName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Manufacturer() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAboutDataViewStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView>) GetDataBySessionPortAsync(param::hstring const& uniqueName, winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment, uint16_t sessionPort) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView>) GetDataBySessionPortAsync(param::hstring const& uniqueName, winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment, uint16_t sessionPort, winrt::Windows::Globalization::Language const& language) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAboutDataViewStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoiner
    {
        WINRT_IMPL_AUTO(void) Accept() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoiner<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UniqueName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) SessionPort() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynTrafficType) TrafficType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SamePhysicalNode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SameNetwork() const;
        WINRT_IMPL_AUTO(void) Accept() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs) Create(param::hstring const& uniqueName, uint16_t sessionPort, winrt::Windows::Devices::AllJoyn::AllJoynTrafficType const& trafficType, uint8_t proximity, winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner const& acceptSessionJoiner) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynAuthenticationCompleteEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism) AuthenticationMechanism() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PeerUniqueName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Succeeded() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynAuthenticationCompleteEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynAboutData) AboutData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ConnectionSpecification() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UniqueName() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<int32_t>) PingAsync(param::hstring const& uniqueName) const;
        WINRT_IMPL_AUTO(void) Connect() const;
        WINRT_IMPL_AUTO(void) Disconnect() const;
        WINRT_IMPL_AUTO(winrt::event_token) StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> const& handler) const;
        using StateChanged_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>::remove_StateChanged>;
        [[nodiscard]] StateChanged_revoker StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StateChanged(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>) AuthenticationMechanisms() const;
        WINRT_IMPL_AUTO(winrt::event_token) CredentialsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> const& handler) const;
        using CredentialsRequested_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>::remove_CredentialsRequested>;
        [[nodiscard]] CredentialsRequested_revoker CredentialsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) CredentialsRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) CredentialsVerificationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> const& handler) const;
        using CredentialsVerificationRequested_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>::remove_CredentialsVerificationRequested>;
        [[nodiscard]] CredentialsVerificationRequested_revoker CredentialsVerificationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) CredentialsVerificationRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AuthenticationComplete(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> const& handler) const;
        using AuthenticationComplete_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>::remove_AuthenticationComplete>;
        [[nodiscard]] AuthenticationComplete_revoker AuthenticationComplete(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AuthenticationComplete(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView>) GetAboutDataAsync(winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView>) GetAboutDataAsync(winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo, winrt::Windows::Globalization::Language const& language) const;
        WINRT_IMPL_AUTO(winrt::event_token) AcceptSessionJoinerRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> const& handler) const;
        using AcceptSessionJoinerRequested_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2>::remove_AcceptSessionJoinerRequested>;
        [[nodiscard]] AcceptSessionJoinerRequested_revoker AcceptSessionJoinerRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AcceptSessionJoinerRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SessionJoined(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> const& handler) const;
        using SessionJoined_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2>::remove_SessionJoined>;
        [[nodiscard]] SessionJoined_revoker SessionJoined(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment, winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SessionJoined(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment) Create(param::hstring const& connectionSpecification) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStateChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStateChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcher) GetWatcher(param::iterable<hstring> const& requiredInterfaces) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusObject
    {
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(void) AddProducer(winrt::Windows::Devices::AllJoyn::IAllJoynProducer const& producer) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment) BusAttachment() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSession) Session() const;
        WINRT_IMPL_AUTO(winrt::event_token) Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusObject, winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> const& handler) const;
        using Stopped_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject>::remove_Stopped>;
        [[nodiscard]] Stopped_revoker Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynBusObject, winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Stopped(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusObjectFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusObject) Create(param::hstring const& objectPath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusObject) CreateWithBusAttachment(param::hstring const& objectPath, winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusObjectFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusObjectStoppedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusObjectStoppedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynBusObjectStoppedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs) Create(int32_t status) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynBusObjectStoppedEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynCredentials
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism) AuthenticationMechanism() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) Certificate() const;
        WINRT_IMPL_AUTO(void) Certificate(winrt::Windows::Security::Cryptography::Certificates::Certificate const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) PasswordCredential() const;
        WINRT_IMPL_AUTO(void) PasswordCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) Timeout() const;
        WINRT_IMPL_AUTO(void) Timeout(winrt::Windows::Foundation::TimeSpan const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) AttemptCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynCredentials) Credentials() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PeerUniqueName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RequestedUserName() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism) AuthenticationMechanism() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PeerUniqueName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) PeerCertificate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketSslErrorSeverity) PeerCertificateErrorSeverity() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>) PeerCertificateErrors() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>) PeerIntermediateCertificates() const;
        WINRT_IMPL_AUTO(void) Accept() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynMessageInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SenderUniqueName() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynMessageInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynMessageInfoFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynMessageInfo) Create(param::hstring const& senderUniqueName) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynMessageInfoFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynProducer
    {
        WINRT_IMPL_AUTO(void) SetBusObject(winrt::Windows::Devices::AllJoyn::AllJoynBusObject const& busObject) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynProducer>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynProducer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynProducerStoppedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynProducerStoppedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynProducerStoppedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs) Create(int32_t status) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynProducerStoppedEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynServiceInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UniqueName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ObjectPath() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) SessionPort() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynServiceInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo) Create(param::hstring const& uniqueName, param::hstring const& objectPath, uint16_t sessionPort) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoRemovedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UniqueName() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoRemovedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoRemovedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs) Create(param::hstring const& uniqueName) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoRemovedEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSession
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Status() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<int32_t>) RemoveMemberAsync(param::hstring const& uniqueName) const;
        WINRT_IMPL_AUTO(winrt::event_token) MemberAdded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynSession, winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> const& handler) const;
        using MemberAdded_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynSession, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynSession>::remove_MemberAdded>;
        [[nodiscard]] MemberAdded_revoker MemberAdded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynSession, winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MemberAdded(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) MemberRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynSession, winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> const& handler) const;
        using MemberRemoved_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynSession, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynSession>::remove_MemberRemoved>;
        [[nodiscard]] MemberRemoved_revoker MemberRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynSession, winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MemberRemoved(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Lost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynSession, winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> const& handler) const;
        using Lost_revoker = impl::event_revoker<winrt::Windows::Devices::AllJoyn::IAllJoynSession, &impl::abi_t<winrt::Windows::Devices::AllJoyn::IAllJoynSession>::remove_Lost>;
        [[nodiscard]] Lost_revoker Lost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::AllJoyn::AllJoynSession, winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Lost(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSession>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSession<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionJoinedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSession) Session() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionJoinedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionJoinedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs) Create(winrt::Windows::Devices::AllJoyn::AllJoynSession const& session) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionJoinedEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionLostEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSessionLostReason) Reason() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionLostEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionLostEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs) Create(winrt::Windows::Devices::AllJoyn::AllJoynSessionLostReason const& reason) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionLostEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberAddedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UniqueName() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberAddedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberAddedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs) Create(param::hstring const& uniqueName) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberAddedEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberRemovedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UniqueName() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberRemovedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberRemovedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs) Create(param::hstring const& uniqueName) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberRemovedEventArgsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynSessionStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynSession>) GetFromServiceInfoAsync(winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::AllJoyn::AllJoynSession>) GetFromServiceInfoAsync(winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo, winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynSessionStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Ok() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Fail() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) OperationTimedOut() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) OtherEndClosed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ConnectionRefused() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) AuthenticationFailed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) AuthenticationRejectedByUser() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) SslConnectFailed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) SslIdentityVerificationFailed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InsufficientSecurity() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument1() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument3() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument4() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument6() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument7() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) InvalidArgument8() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynWatcherStoppedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynWatcherStoppedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_AllJoyn_IAllJoynWatcherStoppedEventArgsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs) Create(int32_t status) const;
    };
    template <> struct consume<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory>
    {
        template <typename D> using type = consume_Windows_Devices_AllJoyn_IAllJoynWatcherStoppedEventArgsFactory<D>;
    };
}
#endif
