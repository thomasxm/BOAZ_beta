// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_WiFiDirect_Services_0_H
#define WINRT_Windows_Devices_WiFiDirect_Services_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration
{
    struct DeviceInformation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Networking
{
    struct EndpointPair;
}
WINRT_EXPORT namespace winrt::Windows::Networking::Sockets
{
    struct DatagramSocket;
    struct StreamSocketListener;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::Devices::WiFiDirect::Services
{
    enum class WiFiDirectServiceAdvertisementStatus : int32_t
    {
        Created = 0,
        Started = 1,
        Stopped = 2,
        Aborted = 3,
    };
    enum class WiFiDirectServiceConfigurationMethod : int32_t
    {
        Default = 0,
        PinDisplay = 1,
        PinEntry = 2,
    };
    enum class WiFiDirectServiceError : int32_t
    {
        Success = 0,
        RadioNotAvailable = 1,
        ResourceInUse = 2,
        UnsupportedHardware = 3,
        NoHardware = 4,
    };
    enum class WiFiDirectServiceIPProtocol : int32_t
    {
        Tcp = 6,
        Udp = 17,
    };
    enum class WiFiDirectServiceSessionErrorStatus : int32_t
    {
        Ok = 0,
        Disassociated = 1,
        LocalClose = 2,
        RemoteClose = 3,
        SystemFailure = 4,
        NoResponseFromRemote = 5,
    };
    enum class WiFiDirectServiceSessionStatus : int32_t
    {
        Closed = 0,
        Initiated = 1,
        Requested = 2,
        Open = 3,
    };
    enum class WiFiDirectServiceStatus : int32_t
    {
        Available = 0,
        Busy = 1,
        Custom = 2,
    };
    struct IWiFiDirectService;
    struct IWiFiDirectServiceAdvertiser;
    struct IWiFiDirectServiceAdvertiserFactory;
    struct IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs;
    struct IWiFiDirectServiceProvisioningInfo;
    struct IWiFiDirectServiceRemotePortAddedEventArgs;
    struct IWiFiDirectServiceSession;
    struct IWiFiDirectServiceSessionDeferredEventArgs;
    struct IWiFiDirectServiceSessionRequest;
    struct IWiFiDirectServiceSessionRequestedEventArgs;
    struct IWiFiDirectServiceStatics;
    struct WiFiDirectService;
    struct WiFiDirectServiceAdvertiser;
    struct WiFiDirectServiceAutoAcceptSessionConnectedEventArgs;
    struct WiFiDirectServiceProvisioningInfo;
    struct WiFiDirectServiceRemotePortAddedEventArgs;
    struct WiFiDirectServiceSession;
    struct WiFiDirectServiceSessionDeferredEventArgs;
    struct WiFiDirectServiceSessionRequest;
    struct WiFiDirectServiceSessionRequestedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectService";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceAdvertiser";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceAutoAcceptSessionConnectedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceProvisioningInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceRemotePortAddedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceSessionDeferredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceSessionRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceSessionRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceAdvertisementStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceConfigurationMethod";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceError";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceIPProtocol";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceSessionErrorStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceSessionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus> = L"Windows.Devices.WiFiDirect.Services.WiFiDirectServiceStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectService";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceAdvertiser";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceAdvertiserFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceProvisioningInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceRemotePortAddedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceSessionDeferredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceSessionRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceSessionRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics> = L"Windows.Devices.WiFiDirect.Services.IWiFiDirectServiceStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService>{ 0x50AABBB8,0x5F71,0x45EC,{ 0x84,0xF1,0xA1,0xE4,0xFC,0x78,0x79,0xA3 } }; // 50AABBB8-5F71-45EC-84F1-A1E4FC7879A3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>{ 0xA4AA1EE1,0x9D8F,0x4F4F,{ 0x93,0xEE,0x7D,0xDE,0xA2,0xE3,0x7F,0x46 } }; // A4AA1EE1-9D8F-4F4F-93EE-7DDEA2E37F46
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>{ 0x3106AC0D,0xB446,0x4F13,{ 0x9F,0x9A,0x8A,0xE9,0x25,0xFE,0xBA,0x2B } }; // 3106AC0D-B446-4F13-9F9A-8AE925FEBA2B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs>{ 0xDCD9E01E,0x83DF,0x43E5,{ 0x8F,0x43,0xCB,0xE8,0x47,0x9E,0x84,0xEB } }; // DCD9E01E-83DF-43E5-8F43-CBE8479E84EB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo>{ 0x8BDB7CFE,0x97D9,0x45A2,{ 0x8E,0x99,0xDB,0x50,0x91,0x0F,0xB6,0xA6 } }; // 8BDB7CFE-97D9-45A2-8E99-DB50910FB6A6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs>{ 0xD4CEBAC1,0x3FD3,0x4F0E,{ 0xB7,0xBD,0x78,0x29,0x06,0xF4,0x44,0x11 } }; // D4CEBAC1-3FD3-4F0E-B7BD-782906F44411
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>{ 0x81142163,0xE426,0x47CB,{ 0x86,0x40,0xE1,0xB3,0x58,0x8B,0xF2,0x6F } }; // 81142163-E426-47CB-8640-E1B3588BF26F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs>{ 0x8DFC197F,0x1201,0x4F1F,{ 0xB6,0xF4,0x5D,0xF1,0xB7,0xB9,0xFB,0x2E } }; // 8DFC197F-1201-4F1F-B6F4-5DF1B7B9FB2E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest>{ 0xA0E27C8B,0x50CB,0x4A58,{ 0x9B,0xCF,0xE4,0x72,0xB9,0x9F,0xBA,0x04 } }; // A0E27C8B-50CB-4A58-9BCF-E472B99FBA04
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs>{ 0x74BDCC11,0x53D6,0x4999,{ 0xB4,0xF8,0x6C,0x8E,0xCC,0x17,0x71,0xE7 } }; // 74BDCC11-53D6-4999-B4F8-6C8ECC1771E7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>{ 0x7DB40045,0xFD74,0x4688,{ 0xB7,0x25,0x5D,0xCE,0x86,0xAC,0xF2,0x33 } }; // 7DB40045-FD74-4688-B725-5DCE86ACF233
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest; };
    template <> struct default_interface<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs>{ using type = winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs; };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RemoteServiceInfo(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedConfigurationMethods(void**) noexcept = 0;
            virtual int32_t __stdcall get_PreferGroupOwnerMode(bool*) noexcept = 0;
            virtual int32_t __stdcall put_PreferGroupOwnerMode(bool) noexcept = 0;
            virtual int32_t __stdcall get_SessionInfo(void**) noexcept = 0;
            virtual int32_t __stdcall put_SessionInfo(void*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceError(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_SessionDeferred(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SessionDeferred(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall GetProvisioningInfoAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ConnectAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ConnectAsyncWithPin(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ServiceName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ServiceNamePrefixes(void**) noexcept = 0;
            virtual int32_t __stdcall get_ServiceInfo(void**) noexcept = 0;
            virtual int32_t __stdcall put_ServiceInfo(void*) noexcept = 0;
            virtual int32_t __stdcall get_AutoAcceptSession(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AutoAcceptSession(bool) noexcept = 0;
            virtual int32_t __stdcall get_PreferGroupOwnerMode(bool*) noexcept = 0;
            virtual int32_t __stdcall put_PreferGroupOwnerMode(bool) noexcept = 0;
            virtual int32_t __stdcall get_PreferredConfigurationMethods(void**) noexcept = 0;
            virtual int32_t __stdcall get_ServiceStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ServiceStatus(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CustomServiceStatusCode(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CustomServiceStatusCode(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_DeferredSessionInfo(void**) noexcept = 0;
            virtual int32_t __stdcall put_DeferredSessionInfo(void*) noexcept = 0;
            virtual int32_t __stdcall get_AdvertisementStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceError(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_SessionRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SessionRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AutoAcceptSessionConnected(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AutoAcceptSessionConnected(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AdvertisementStatusChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AdvertisementStatusChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall ConnectAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ConnectAsyncWithPin(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWiFiDirectServiceAdvertiser(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Session(void**) noexcept = 0;
            virtual int32_t __stdcall get_SessionInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SelectedConfigurationMethod(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsGroupFormationNeeded(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EndpointPairs(void**) noexcept = 0;
            virtual int32_t __stdcall get_Protocol(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ServiceName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ErrorStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SessionId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AdvertisementId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceAddress(void**) noexcept = 0;
            virtual int32_t __stdcall get_SessionAddress(void**) noexcept = 0;
            virtual int32_t __stdcall GetConnectionEndpointPairs(void**) noexcept = 0;
            virtual int32_t __stdcall add_SessionStatusChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SessionStatusChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall AddStreamSocketListenerAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddDatagramSocketAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_RemotePortAdded(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RemotePortAdded(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeferredSessionInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceInformation(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProvisioningInfo(void**) noexcept = 0;
            virtual int32_t __stdcall get_SessionInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetSessionRequest(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetSelector(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSelectorWithFilter(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) RemoteServiceInfo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>) SupportedConfigurationMethods() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) PreferGroupOwnerMode() const;
        WINRT_IMPL_AUTO(void) PreferGroupOwnerMode(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) SessionInfo() const;
        WINRT_IMPL_AUTO(void) SessionInfo(winrt::Windows::Storage::Streams::IBuffer const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError) ServiceError() const;
        WINRT_IMPL_AUTO(winrt::event_token) SessionDeferred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const& handler) const;
        using SessionDeferred_revoker = impl::event_revoker<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService, &impl::abi_t<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService>::remove_SessionDeferred>;
        [[nodiscard]] SessionDeferred_revoker SessionDeferred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SessionDeferred(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>) GetProvisioningInfoAsync(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod const& selectedConfigurationMethod) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) ConnectAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) ConnectAsync(param::hstring const& pin) const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ServiceName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) ServiceNamePrefixes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) ServiceInfo() const;
        WINRT_IMPL_AUTO(void) ServiceInfo(winrt::Windows::Storage::Streams::IBuffer const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AutoAcceptSession() const;
        WINRT_IMPL_AUTO(void) AutoAcceptSession(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) PreferGroupOwnerMode() const;
        WINRT_IMPL_AUTO(void) PreferGroupOwnerMode(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>) PreferredConfigurationMethods() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus) ServiceStatus() const;
        WINRT_IMPL_AUTO(void) ServiceStatus(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CustomServiceStatusCode() const;
        WINRT_IMPL_AUTO(void) CustomServiceStatusCode(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DeferredSessionInfo() const;
        WINRT_IMPL_AUTO(void) DeferredSessionInfo(winrt::Windows::Storage::Streams::IBuffer const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus) AdvertisementStatus() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError) ServiceError() const;
        WINRT_IMPL_AUTO(winrt::event_token) SessionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const& handler) const;
        using SessionRequested_revoker = impl::event_revoker<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser, &impl::abi_t<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>::remove_SessionRequested>;
        [[nodiscard]] SessionRequested_revoker SessionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SessionRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AutoAcceptSessionConnected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const& handler) const;
        using AutoAcceptSessionConnected_revoker = impl::event_revoker<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser, &impl::abi_t<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>::remove_AutoAcceptSessionConnected>;
        [[nodiscard]] AutoAcceptSessionConnected_revoker AutoAcceptSessionConnected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AutoAcceptSessionConnected(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AdvertisementStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using AdvertisementStatusChanged_revoker = impl::event_revoker<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser, &impl::abi_t<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>::remove_AdvertisementStatusChanged>;
        [[nodiscard]] AdvertisementStatusChanged_revoker AdvertisementStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) AdvertisementStatusChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) ConnectAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) ConnectAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInfo, param::hstring const& pin) const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiserFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser) CreateWiFiDirectServiceAdvertiser(param::hstring const& serviceName) const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiserFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession) Session() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) SessionInfo() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceProvisioningInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod) SelectedConfigurationMethod() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsGroupFormationNeeded() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceProvisioningInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceRemotePortAddedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>) EndpointPairs() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol) Protocol() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceRemotePortAddedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ServiceName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus) ErrorStatus() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SessionId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) AdvertisementId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ServiceAddress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SessionAddress() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>) GetConnectionEndpointPairs() const;
        WINRT_IMPL_AUTO(winrt::event_token) SessionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SessionStatusChanged_revoker = impl::event_revoker<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession, &impl::abi_t<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>::remove_SessionStatusChanged>;
        [[nodiscard]] SessionStatusChanged_revoker SessionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SessionStatusChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AddStreamSocketListenerAsync(winrt::Windows::Networking::Sockets::StreamSocketListener const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AddDatagramSocketAsync(winrt::Windows::Networking::Sockets::DatagramSocket const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) RemotePortAdded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const& handler) const;
        using RemotePortAdded_revoker = impl::event_revoker<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession, &impl::abi_t<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>::remove_RemotePortAdded>;
        [[nodiscard]] RemotePortAdded_revoker RemotePortAdded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) RemotePortAdded(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionDeferredEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DeferredSessionInfo() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionDeferredEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) DeviceInformation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo) ProvisioningInfo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) SessionInfo() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequestedEventArgs
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest) GetSessionRequest() const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics
    {
        WINRT_IMPL_AUTO(hstring) GetSelector(param::hstring const& serviceName) const;
        WINRT_IMPL_AUTO(hstring) GetSelector(param::hstring const& serviceName, winrt::Windows::Storage::Streams::IBuffer const& serviceInfoFilter) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>;
    };
}
#endif
