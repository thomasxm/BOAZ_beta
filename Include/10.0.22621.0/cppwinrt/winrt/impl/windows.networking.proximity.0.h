// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_Proximity_0_H
#define WINRT_Windows_Networking_Proximity_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMap;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Networking
{
    struct HostName;
}
WINRT_EXPORT namespace winrt::Windows::Networking::Sockets
{
    struct StreamSocket;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::Networking::Proximity
{
    enum class PeerDiscoveryTypes : uint32_t
    {
        None = 0,
        Browse = 0x1,
        Triggered = 0x2,
    };
    enum class PeerRole : int32_t
    {
        Peer = 0,
        Host = 1,
        Client = 2,
    };
    enum class PeerWatcherStatus : int32_t
    {
        Created = 0,
        Started = 1,
        EnumerationCompleted = 2,
        Stopping = 3,
        Stopped = 4,
        Aborted = 5,
    };
    enum class TriggeredConnectState : int32_t
    {
        PeerFound = 0,
        Listening = 1,
        Connecting = 2,
        Completed = 3,
        Canceled = 4,
        Failed = 5,
    };
    struct IConnectionRequestedEventArgs;
    struct IPeerFinderStatics;
    struct IPeerFinderStatics2;
    struct IPeerInformation;
    struct IPeerInformation3;
    struct IPeerInformationWithHostAndService;
    struct IPeerWatcher;
    struct IProximityDevice;
    struct IProximityDeviceStatics;
    struct IProximityMessage;
    struct ITriggeredConnectionStateChangedEventArgs;
    struct ConnectionRequestedEventArgs;
    struct PeerFinder;
    struct PeerInformation;
    struct PeerWatcher;
    struct ProximityDevice;
    struct ProximityMessage;
    struct TriggeredConnectionStateChangedEventArgs;
    struct DeviceArrivedEventHandler;
    struct DeviceDepartedEventHandler;
    struct MessageReceivedHandler;
    struct MessageTransmittedHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IPeerFinderStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IPeerFinderStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IPeerInformation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IPeerInformation3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IPeerWatcher>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IProximityDevice>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IProximityDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::IProximityMessage>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::PeerFinder>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::PeerInformation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::PeerWatcher>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::ProximityDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::ProximityMessage>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::PeerDiscoveryTypes>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::PeerRole>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::PeerWatcherStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::TriggeredConnectState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::MessageReceivedHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Networking::Proximity::MessageTransmittedHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> = L"Windows.Networking.Proximity.ConnectionRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::PeerFinder> = L"Windows.Networking.Proximity.PeerFinder";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::PeerInformation> = L"Windows.Networking.Proximity.PeerInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::PeerWatcher> = L"Windows.Networking.Proximity.PeerWatcher";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::ProximityDevice> = L"Windows.Networking.Proximity.ProximityDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::ProximityMessage> = L"Windows.Networking.Proximity.ProximityMessage";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> = L"Windows.Networking.Proximity.TriggeredConnectionStateChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::PeerDiscoveryTypes> = L"Windows.Networking.Proximity.PeerDiscoveryTypes";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::PeerRole> = L"Windows.Networking.Proximity.PeerRole";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::PeerWatcherStatus> = L"Windows.Networking.Proximity.PeerWatcherStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::TriggeredConnectState> = L"Windows.Networking.Proximity.TriggeredConnectState";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs> = L"Windows.Networking.Proximity.IConnectionRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IPeerFinderStatics> = L"Windows.Networking.Proximity.IPeerFinderStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IPeerFinderStatics2> = L"Windows.Networking.Proximity.IPeerFinderStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IPeerInformation> = L"Windows.Networking.Proximity.IPeerInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IPeerInformation3> = L"Windows.Networking.Proximity.IPeerInformation3";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService> = L"Windows.Networking.Proximity.IPeerInformationWithHostAndService";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IPeerWatcher> = L"Windows.Networking.Proximity.IPeerWatcher";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IProximityDevice> = L"Windows.Networking.Proximity.IProximityDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IProximityDeviceStatics> = L"Windows.Networking.Proximity.IProximityDeviceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::IProximityMessage> = L"Windows.Networking.Proximity.IProximityMessage";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> = L"Windows.Networking.Proximity.ITriggeredConnectionStateChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler> = L"Windows.Networking.Proximity.DeviceArrivedEventHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler> = L"Windows.Networking.Proximity.DeviceDepartedEventHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::MessageReceivedHandler> = L"Windows.Networking.Proximity.MessageReceivedHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::Networking::Proximity::MessageTransmittedHandler> = L"Windows.Networking.Proximity.MessageTransmittedHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs>{ 0xEB6891AE,0x4F1E,0x4C66,{ 0xBD,0x0D,0x46,0x92,0x4A,0x94,0x2E,0x08 } }; // EB6891AE-4F1E-4C66-BD0D-46924A942E08
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IPeerFinderStatics>{ 0x914B3B61,0xF6E1,0x47C4,{ 0xA1,0x4C,0x14,0x8A,0x19,0x03,0xD0,0xC6 } }; // 914B3B61-F6E1-47C4-A14C-148A1903D0C6
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IPeerFinderStatics2>{ 0xD6E73C65,0xFDD0,0x4B0B,{ 0x93,0x12,0x86,0x64,0x08,0x93,0x5D,0x82 } }; // D6E73C65-FDD0-4B0B-9312-866408935D82
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IPeerInformation>{ 0x20024F08,0x9FFF,0x45F4,{ 0xB6,0xE9,0x40,0x8B,0x2E,0xBE,0xF3,0x73 } }; // 20024F08-9FFF-45F4-B6E9-408B2EBEF373
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IPeerInformation3>{ 0xB20F612A,0xDBD0,0x40F8,{ 0x95,0xBD,0x2D,0x42,0x09,0xC7,0x83,0x6F } }; // B20F612A-DBD0-40F8-95BD-2D4209C7836F
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService>{ 0xECC7CCAD,0x1B70,0x4E8B,{ 0x92,0xDB,0xBB,0xE7,0x81,0x41,0x93,0x08 } }; // ECC7CCAD-1B70-4E8B-92DB-BBE781419308
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IPeerWatcher>{ 0x3CEE21F8,0x2FA6,0x4679,{ 0x96,0x91,0x03,0xC9,0x4A,0x42,0x0F,0x34 } }; // 3CEE21F8-2FA6-4679-9691-03C94A420F34
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IProximityDevice>{ 0xEFA8A552,0xF6E1,0x4329,{ 0xA0,0xFC,0xAB,0x6B,0x0F,0xD2,0x82,0x62 } }; // EFA8A552-F6E1-4329-A0FC-AB6B0FD28262
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IProximityDeviceStatics>{ 0x914BA01D,0xF6E1,0x47C4,{ 0xA1,0x4C,0x14,0x8A,0x19,0x03,0xD0,0xC6 } }; // 914BA01D-F6E1-47C4-A14C-148A1903D0C6
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::IProximityMessage>{ 0xEFAB0782,0xF6E1,0x4675,{ 0xA0,0x45,0xD8,0xE3,0x20,0xC2,0x48,0x08 } }; // EFAB0782-F6E1-4675-A045-D8E320C24808
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>{ 0xC6A780AD,0xF6E1,0x4D54,{ 0x96,0xE2,0x33,0xF6,0x20,0xBC,0xA8,0x8A } }; // C6A780AD-F6E1-4D54-96E2-33F620BCA88A
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler>{ 0xEFA9DA69,0xF6E1,0x49C9,{ 0xA4,0x9E,0x8E,0x0F,0xC5,0x8F,0xB9,0x11 } }; // EFA9DA69-F6E1-49C9-A49E-8E0FC58FB911
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler>{ 0xEFA9DA69,0xF6E2,0x49C9,{ 0xA4,0x9E,0x8E,0x0F,0xC5,0x8F,0xB9,0x11 } }; // EFA9DA69-F6E2-49C9-A49E-8E0FC58FB911
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::MessageReceivedHandler>{ 0xEFAB0782,0xF6E2,0x4675,{ 0xA0,0x45,0xD8,0xE3,0x20,0xC2,0x48,0x08 } }; // EFAB0782-F6E2-4675-A045-D8E320C24808
    template <> inline constexpr guid guid_v<winrt::Windows::Networking::Proximity::MessageTransmittedHandler>{ 0xEFAA0B4A,0xF6E2,0x4D7D,{ 0x85,0x6C,0x78,0xFC,0x8E,0xFC,0x02,0x1E } }; // EFAA0B4A-F6E2-4D7D-856C-78FC8EFC021E
    template <> struct default_interface<winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs>{ using type = winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Networking::Proximity::PeerInformation>{ using type = winrt::Windows::Networking::Proximity::IPeerInformation; };
    template <> struct default_interface<winrt::Windows::Networking::Proximity::PeerWatcher>{ using type = winrt::Windows::Networking::Proximity::IPeerWatcher; };
    template <> struct default_interface<winrt::Windows::Networking::Proximity::ProximityDevice>{ using type = winrt::Windows::Networking::Proximity::IProximityDevice; };
    template <> struct default_interface<winrt::Windows::Networking::Proximity::ProximityMessage>{ using type = winrt::Windows::Networking::Proximity::IProximityMessage; };
    template <> struct default_interface<winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs>{ using type = winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs; };
    template <> struct abi<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PeerInformation(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IPeerFinderStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowBluetooth(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowBluetooth(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowInfrastructure(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowInfrastructure(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowWiFiDirect(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowWiFiDirect(bool) noexcept = 0;
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedDiscoveryTypes(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AlternateIdentities(void**) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall StartWithMessage(void*) noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall add_TriggeredConnectionStateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_TriggeredConnectionStateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ConnectionRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ConnectionRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall FindAllPeersAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ConnectAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IPeerFinderStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Role(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Role(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_DiscoveryData(void**) noexcept = 0;
            virtual int32_t __stdcall put_DiscoveryData(void*) noexcept = 0;
            virtual int32_t __stdcall CreateWatcher(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IPeerInformation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IPeerInformation3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall get_DiscoveryData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HostName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ServiceName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IPeerWatcher>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Added(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Added(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Removed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Removed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Updated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Updated(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_EnumerationCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_EnumerationCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Stopped(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Stopped(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IProximityDevice>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SubscribeForMessage(void*, void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall PublishMessage(void*, void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall PublishMessageWithCallback(void*, void*, void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall PublishBinaryMessage(void*, void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall PublishBinaryMessageWithCallback(void*, void*, void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall PublishUriMessage(void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall PublishUriMessageWithCallback(void*, void*, int64_t*) noexcept = 0;
            virtual int32_t __stdcall StopSubscribingForMessage(int64_t) noexcept = 0;
            virtual int32_t __stdcall StopPublishingMessage(int64_t) noexcept = 0;
            virtual int32_t __stdcall add_DeviceArrived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DeviceArrived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_DeviceDeparted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DeviceDeparted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_MaxMessageBytes(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_BitsPerSecond(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IProximityDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall FromId(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::IProximityMessage>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MessageType(void**) noexcept = 0;
            virtual int32_t __stdcall get_SubscriptionId(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall get_DataAsString(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Id(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Socket(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::MessageReceivedHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Networking::Proximity::MessageTransmittedHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*, int64_t) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IConnectionRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerInformation) PeerInformation() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IConnectionRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IPeerFinderStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowBluetooth() const;
        WINRT_IMPL_AUTO(void) AllowBluetooth(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowInfrastructure() const;
        WINRT_IMPL_AUTO(void) AllowInfrastructure(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowWiFiDirect() const;
        WINRT_IMPL_AUTO(void) AllowWiFiDirect(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        WINRT_IMPL_AUTO(void) DisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerDiscoveryTypes) SupportedDiscoveryTypes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) AlternateIdentities() const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Start(param::hstring const& peerMessage) const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(winrt::event_token) TriggeredConnectionStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const;
        using TriggeredConnectionStateChanged_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerFinderStatics, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerFinderStatics>::remove_TriggeredConnectionStateChanged>;
        [[nodiscard]] TriggeredConnectionStateChanged_revoker TriggeredConnectionStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) TriggeredConnectionStateChanged(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ConnectionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const;
        using ConnectionRequested_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerFinderStatics, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerFinderStatics>::remove_ConnectionRequested>;
        [[nodiscard]] ConnectionRequested_revoker ConnectionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ConnectionRequested(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::Proximity::PeerInformation>>) FindAllPeersAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::Sockets::StreamSocket>) ConnectAsync(winrt::Windows::Networking::Proximity::PeerInformation const& peerInformation) const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IPeerFinderStatics>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IPeerFinderStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IPeerFinderStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerRole) Role() const;
        WINRT_IMPL_AUTO(void) Role(winrt::Windows::Networking::Proximity::PeerRole const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DiscoveryData() const;
        WINRT_IMPL_AUTO(void) DiscoveryData(winrt::Windows::Storage::Streams::IBuffer const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerWatcher) CreateWatcher() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IPeerFinderStatics2>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IPeerInformation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IPeerInformation>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IPeerInformation<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IPeerInformation3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DiscoveryData() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IPeerInformation3>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IPeerInformation3<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) HostName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ServiceName() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IPeerWatcher
    {
        WINRT_IMPL_AUTO(winrt::event_token) Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const;
        using Added_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerWatcher>::remove_Added>;
        [[nodiscard]] Added_revoker Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const;
        WINRT_IMPL_AUTO(void) Added(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const;
        using Removed_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerWatcher>::remove_Removed>;
        [[nodiscard]] Removed_revoker Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const;
        WINRT_IMPL_AUTO(void) Removed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const;
        using Updated_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerWatcher>::remove_Updated>;
        [[nodiscard]] Updated_revoker Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const;
        WINRT_IMPL_AUTO(void) Updated(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using EnumerationCompleted_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerWatcher>::remove_EnumerationCompleted>;
        [[nodiscard]] EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) EnumerationCompleted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using Stopped_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<winrt::Windows::Networking::Proximity::IPeerWatcher>::remove_Stopped>;
        [[nodiscard]] Stopped_revoker Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) Stopped(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerWatcherStatus) Status() const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IPeerWatcher>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IPeerWatcher<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IProximityDevice
    {
        WINRT_IMPL_AUTO(int64_t) SubscribeForMessage(param::hstring const& messageType, winrt::Windows::Networking::Proximity::MessageReceivedHandler const& messageReceivedHandler) const;
        WINRT_IMPL_AUTO(int64_t) PublishMessage(param::hstring const& messageType, param::hstring const& message) const;
        WINRT_IMPL_AUTO(int64_t) PublishMessage(param::hstring const& messageType, param::hstring const& message, winrt::Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const;
        WINRT_IMPL_AUTO(int64_t) PublishBinaryMessage(param::hstring const& messageType, winrt::Windows::Storage::Streams::IBuffer const& message) const;
        WINRT_IMPL_AUTO(int64_t) PublishBinaryMessage(param::hstring const& messageType, winrt::Windows::Storage::Streams::IBuffer const& message, winrt::Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const;
        WINRT_IMPL_AUTO(int64_t) PublishUriMessage(winrt::Windows::Foundation::Uri const& message) const;
        WINRT_IMPL_AUTO(int64_t) PublishUriMessage(winrt::Windows::Foundation::Uri const& message, winrt::Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const;
        WINRT_IMPL_AUTO(void) StopSubscribingForMessage(int64_t subscriptionId) const;
        WINRT_IMPL_AUTO(void) StopPublishingMessage(int64_t messageId) const;
        WINRT_IMPL_AUTO(winrt::event_token) DeviceArrived(winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const;
        using DeviceArrived_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IProximityDevice, &impl::abi_t<winrt::Windows::Networking::Proximity::IProximityDevice>::remove_DeviceArrived>;
        [[nodiscard]] DeviceArrived_revoker DeviceArrived(auto_revoke_t, winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const;
        WINRT_IMPL_AUTO(void) DeviceArrived(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) DeviceDeparted(winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const;
        using DeviceDeparted_revoker = impl::event_revoker<winrt::Windows::Networking::Proximity::IProximityDevice, &impl::abi_t<winrt::Windows::Networking::Proximity::IProximityDevice>::remove_DeviceDeparted>;
        [[nodiscard]] DeviceDeparted_revoker DeviceDeparted(auto_revoke_t, winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const;
        WINRT_IMPL_AUTO(void) DeviceDeparted(winrt::event_token const& cookie) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxMessageBytes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) BitsPerSecond() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IProximityDevice>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IProximityDevice<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IProximityDeviceStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::ProximityDevice) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::ProximityDevice) FromId(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IProximityDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_IProximityMessage
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) MessageType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int64_t) SubscriptionId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Data() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DataAsString() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::IProximityMessage>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_IProximityMessage<D>;
    };
    template <typename D>
    struct consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::TriggeredConnectState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocket) Socket() const;
    };
    template <> struct consume<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>;
    };
}
#endif
