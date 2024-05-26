// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Phone_Networking_Voip_0_H
#define WINRT_Windows_Phone_Networking_Voip_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Phone::Networking::Voip
{
    enum class SeamlessCallUpgradeSupport : int32_t
    {
        Unknown = 0,
        NotSupported = 1,
        Supported = 2,
    };
    enum class VoipCallMedia : uint32_t
    {
        None = 0,
        Audio = 0x1,
        Video = 0x2,
    };
    enum class VoipCallRejectReason : int32_t
    {
        UserIgnored = 0,
        TimedOut = 1,
        OtherIncomingCall = 2,
        EmergencyCallExists = 3,
        InvalidCallState = 4,
    };
    enum class VoipCallState : int32_t
    {
        Ended = 0,
        Held = 1,
        Active = 2,
        Incoming = 3,
        Outgoing = 4,
    };
    enum class VoipOperationType : int32_t
    {
        QueryRemotePartySeamless = 0,
    };
    struct ICallAnswerEventArgs;
    struct ICallRejectEventArgs;
    struct ICallStateChangeEventArgs;
    struct IMuteChangeEventArgs;
    struct IQuerySeamlessUpgradeSupportOperation;
    struct IVoipCallCoordinator;
    struct IVoipCallCoordinator2;
    struct IVoipCallCoordinator3;
    struct IVoipCallCoordinatorStatics;
    struct IVoipCallCoordinatorWithAppDeterminedUpgrade;
    struct IVoipCallCoordinatorWithUpgrade;
    struct IVoipOperation;
    struct IVoipOperationsManager;
    struct IVoipPhoneCall;
    struct IVoipPhoneCall2;
    struct IVoipPhoneCall3;
    struct IVoipPhoneCallReady;
    struct CallAnswerEventArgs;
    struct CallRejectEventArgs;
    struct CallStateChangeEventArgs;
    struct MuteChangeEventArgs;
    struct QuerySeamlessUpgradeSupportOperation;
    struct VoipCallCoordinator;
    struct VoipPhoneCall;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithAppDeterminedUpgrade>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithUpgrade>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipOperationsManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCallReady>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::CallAnswerEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::CallRejectEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::QuerySeamlessUpgradeSupportOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall>{ using type = class_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::SeamlessCallUpgradeSupport>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::VoipCallMedia>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::VoipCallRejectReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::VoipCallState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Phone::Networking::Voip::VoipOperationType>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::CallAnswerEventArgs> = L"Windows.Phone.Networking.Voip.CallAnswerEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::CallRejectEventArgs> = L"Windows.Phone.Networking.Voip.CallRejectEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> = L"Windows.Phone.Networking.Voip.CallStateChangeEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs> = L"Windows.Phone.Networking.Voip.MuteChangeEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::QuerySeamlessUpgradeSupportOperation> = L"Windows.Phone.Networking.Voip.QuerySeamlessUpgradeSupportOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator> = L"Windows.Phone.Networking.Voip.VoipCallCoordinator";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall> = L"Windows.Phone.Networking.Voip.VoipPhoneCall";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::SeamlessCallUpgradeSupport> = L"Windows.Phone.Networking.Voip.SeamlessCallUpgradeSupport";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::VoipCallMedia> = L"Windows.Phone.Networking.Voip.VoipCallMedia";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::VoipCallRejectReason> = L"Windows.Phone.Networking.Voip.VoipCallRejectReason";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::VoipCallState> = L"Windows.Phone.Networking.Voip.VoipCallState";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::VoipOperationType> = L"Windows.Phone.Networking.Voip.VoipOperationType";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs> = L"Windows.Phone.Networking.Voip.ICallAnswerEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs> = L"Windows.Phone.Networking.Voip.ICallRejectEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs> = L"Windows.Phone.Networking.Voip.ICallStateChangeEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs> = L"Windows.Phone.Networking.Voip.IMuteChangeEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation> = L"Windows.Phone.Networking.Voip.IQuerySeamlessUpgradeSupportOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator> = L"Windows.Phone.Networking.Voip.IVoipCallCoordinator";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2> = L"Windows.Phone.Networking.Voip.IVoipCallCoordinator2";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3> = L"Windows.Phone.Networking.Voip.IVoipCallCoordinator3";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorStatics> = L"Windows.Phone.Networking.Voip.IVoipCallCoordinatorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithAppDeterminedUpgrade> = L"Windows.Phone.Networking.Voip.IVoipCallCoordinatorWithAppDeterminedUpgrade";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithUpgrade> = L"Windows.Phone.Networking.Voip.IVoipCallCoordinatorWithUpgrade";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipOperation> = L"Windows.Phone.Networking.Voip.IVoipOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipOperationsManager> = L"Windows.Phone.Networking.Voip.IVoipOperationsManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall> = L"Windows.Phone.Networking.Voip.IVoipPhoneCall";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2> = L"Windows.Phone.Networking.Voip.IVoipPhoneCall2";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3> = L"Windows.Phone.Networking.Voip.IVoipPhoneCall3";
    template <> inline constexpr auto& name_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCallReady> = L"Windows.Phone.Networking.Voip.IVoipPhoneCallReady";
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs>{ 0x61F132AA,0xF92A,0x48FA,{ 0xAA,0x8F,0x4F,0x3A,0x17,0x66,0x29,0x80 } }; // 61F132AA-F92A-48FA-AA8F-4F3A17662980
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs>{ 0x3E04061A,0xCE7D,0x49C2,{ 0xA2,0xB8,0x7F,0x49,0xB6,0xEA,0xEB,0xC5 } }; // 3E04061A-CE7D-49C2-A2B8-7F49B6EAEBC5
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs>{ 0x1F3E87B0,0xD371,0x4395,{ 0x8B,0x6C,0x17,0x86,0xA4,0x2E,0x2F,0x18 } }; // 1F3E87B0-D371-4395-8B6C-1786A42E2F18
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs>{ 0xF914EAD4,0x1C94,0x458C,{ 0xAC,0xB7,0x19,0x26,0xA2,0x33,0xF7,0x4C } }; // F914EAD4-1C94-458C-ACB7-1926A233F74C
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation>{ 0x7E7ADCCE,0xCF2B,0x4EA0,{ 0x84,0x75,0xE1,0xBD,0xB4,0x14,0x03,0x79 } }; // 7E7ADCCE-CF2B-4EA0-8475-E1BDB4140379
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>{ 0x0D5F3579,0xF6DD,0x4E10,{ 0x9F,0x25,0x3D,0x8C,0x91,0x37,0x6E,0xE8 } }; // 0D5F3579-F6DD-4E10-9F25-3D8C91376EE8
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2>{ 0x0290A9B8,0x645D,0x4711,{ 0x8E,0x32,0x92,0x6B,0xFA,0xBF,0x69,0x28 } }; // 0290A9B8-645D-4711-8E32-926BFABF6928
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3>{ 0x80A2EDE6,0x0D02,0x40CD,{ 0x88,0x91,0xB4,0xCE,0xC6,0x47,0x2C,0x82 } }; // 80A2EDE6-0D02-40CD-8891-B4CEC6472C82
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorStatics>{ 0x10FB55BB,0xE07D,0x407E,{ 0xBC,0x39,0xF7,0xCC,0x36,0x41,0xD9,0x79 } }; // 10FB55BB-E07D-407E-BC39-F7CC3641D979
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithAppDeterminedUpgrade>{ 0x4EC3EDA6,0x9CF0,0x405C,{ 0xBC,0xCD,0xCB,0x7A,0x86,0x32,0xA4,0x56 } }; // 4EC3EDA6-9CF0-405C-BCCD-CB7A8632A456
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithUpgrade>{ 0x6172CCBC,0x6DD1,0x4F8E,{ 0xB9,0x38,0x53,0x93,0x53,0x0C,0x31,0xCA } }; // 6172CCBC-6DD1-4F8E-B938-5393530C31CA
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipOperation>{ 0x559B526D,0xC2CB,0x44D9,{ 0x83,0xA5,0x60,0xCD,0xA4,0xB7,0x1D,0x36 } }; // 559B526D-C2CB-44D9-83A5-60CDA4B71D36
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipOperationsManager>{ 0xBA77E23C,0x38D9,0x4DFB,{ 0x85,0x3F,0xF9,0x01,0x97,0x8F,0xF7,0xFA } }; // BA77E23C-38D9-4DFB-853F-F901978FF7FA
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>{ 0x716654BE,0x28E8,0x495E,{ 0xB6,0x57,0x80,0x53,0x07,0x4B,0x41,0x50 } }; // 716654BE-28E8-495E-B657-8053074B4150
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2>{ 0x1AC5B7DC,0xC83F,0x4862,{ 0x83,0x93,0x1E,0xA1,0x4A,0xF7,0xEF,0xEA } }; // 1AC5B7DC-C83F-4862-8393-1EA14AF7EFEA
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3>{ 0xA92AB1D1,0x52FB,0x4ADF,{ 0x82,0x25,0x4D,0x28,0x9B,0x86,0x6F,0xE0 } }; // A92AB1D1-52FB-4ADF-8225-4D289B866FE0
    template <> inline constexpr guid guid_v<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCallReady>{ 0xB3F5AC79,0xF40F,0x4E52,{ 0xA8,0xEE,0xE8,0xA9,0xA7,0x1F,0x51,0x1A } }; // B3F5AC79-F40F-4E52-A8EE-E8A9A71F511A
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::CallAnswerEventArgs>{ using type = winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs; };
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::CallRejectEventArgs>{ using type = winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs; };
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs>{ using type = winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs; };
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs>{ using type = winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs; };
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::QuerySeamlessUpgradeSupportOperation>{ using type = winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation; };
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator>{ using type = winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator; };
    template <> struct default_interface<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall>{ using type = winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall; };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AcceptedMedia(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RejectReason(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Muted(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RemoteId(void**) noexcept = 0;
            virtual int32_t __stdcall NotifyCompletion(bool, int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_MuteRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MuteRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_UnmuteRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_UnmuteRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall RequestNewIncomingCall(void*, void*, void*, void*, void*, void*, void*, void*, uint32_t, int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall RequestNewOutgoingCall(void*, void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall NotifyMuted() noexcept = 0;
            virtual int32_t __stdcall NotifyUnmuted() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetupNewAcceptedCall(void*, void*, void*, void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestNewIncomingCallWithContactRemoteId(void*, void*, void*, void*, void*, void*, void*, void*, uint32_t, int64_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestNewAppInitiatedCall(void*, void*, void*, void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithAppDeterminedUpgrade>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ConfirmNonSeamlessUpgrade(winrt::guid) noexcept = 0;
            virtual int32_t __stdcall CancelUpgrade(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithUpgrade>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestOutgoingUpgradeToVideoCall(winrt::guid, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestIncomingUpgradeToVideoCall(void*, void*, void*, void*, void*, void*, void*, void*, int64_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Type(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipOperationsManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetNextOperation(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_EndRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_EndRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_HoldRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_HoldRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ResumeRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ResumeRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AnswerRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AnswerRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_RejectRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RejectRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall NotifyCallHeld() noexcept = 0;
            virtual int32_t __stdcall NotifyCallActive() noexcept = 0;
            virtual int32_t __stdcall NotifyCallEnded() noexcept = 0;
            virtual int32_t __stdcall get_ContactName(void**) noexcept = 0;
            virtual int32_t __stdcall put_ContactName(void*) noexcept = 0;
            virtual int32_t __stdcall get_StartTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_StartTime(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_CallMedia(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CallMedia(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryShowAppUI() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall NotifyCallAccepted(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCallReady>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall NotifyCallReady() noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_ICallAnswerEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipCallMedia) AcceptedMedia() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_ICallAnswerEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_ICallRejectEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipCallRejectReason) RejectReason() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_ICallRejectEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_ICallStateChangeEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipCallState) State() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_ICallStateChangeEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IMuteChangeEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Muted() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IMuteChangeEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IQuerySeamlessUpgradeSupportOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RemoteId() const;
        WINRT_IMPL_AUTO(void) NotifyCompletion(bool succeeded, winrt::Windows::Phone::Networking::Voip::SeamlessCallUpgradeSupport const& seamlessCallUpgradeSupport) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IQuerySeamlessUpgradeSupportOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipCallCoordinator
    {
        WINRT_IMPL_AUTO(winrt::event_token) MuteRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator, winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs> const& muteChangeHandler) const;
        using MuteRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>::remove_MuteRequested>;
        [[nodiscard]] MuteRequested_revoker MuteRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator, winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs> const& muteChangeHandler) const;
        WINRT_IMPL_AUTO(void) MuteRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) UnmuteRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator, winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs> const& muteChangeHandler) const;
        using UnmuteRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>::remove_UnmuteRequested>;
        [[nodiscard]] UnmuteRequested_revoker UnmuteRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator, winrt::Windows::Phone::Networking::Voip::MuteChangeEventArgs> const& muteChangeHandler) const;
        WINRT_IMPL_AUTO(void) UnmuteRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) RequestNewIncomingCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, winrt::Windows::Foundation::Uri const& contactImage, param::hstring const& serviceName, winrt::Windows::Foundation::Uri const& brandingImage, param::hstring const& callDetails, winrt::Windows::Foundation::Uri const& ringtone, winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& media, winrt::Windows::Foundation::TimeSpan const& ringTimeout, winrt::Windows::Phone::Networking::Voip::VoipPhoneCall& call) const;
        WINRT_IMPL_AUTO(void) RequestNewOutgoingCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& serviceName, winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& media, winrt::Windows::Phone::Networking::Voip::VoipPhoneCall& call) const;
        WINRT_IMPL_AUTO(void) NotifyMuted() const;
        WINRT_IMPL_AUTO(void) NotifyUnmuted() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipCallCoordinator<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipCallCoordinator2
    {
        WINRT_IMPL_AUTO(void) SetupNewAcceptedCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, param::hstring const& serviceName, winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& media, winrt::Windows::Phone::Networking::Voip::VoipPhoneCall& call) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipCallCoordinator2<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipCallCoordinator3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipPhoneCall) RequestNewIncomingCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, winrt::Windows::Foundation::Uri const& contactImage, param::hstring const& serviceName, winrt::Windows::Foundation::Uri const& brandingImage, param::hstring const& callDetails, winrt::Windows::Foundation::Uri const& ringtone, winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& media, winrt::Windows::Foundation::TimeSpan const& ringTimeout, param::hstring const& contactRemoteId) const;
        WINRT_IMPL_AUTO(void) RequestNewAppInitiatedCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, param::hstring const& serviceName, winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& media, winrt::Windows::Phone::Networking::Voip::VoipPhoneCall& call) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipCallCoordinator3<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipCallCoordinatorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipCallCoordinator) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorStatics>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipCallCoordinatorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipCallCoordinatorWithAppDeterminedUpgrade
    {
        WINRT_IMPL_AUTO(void) ConfirmNonSeamlessUpgrade(winrt::guid const& callUpgradeGuid) const;
        WINRT_IMPL_AUTO(void) CancelUpgrade(winrt::guid const& callUpgradeGuid) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithAppDeterminedUpgrade>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipCallCoordinatorWithAppDeterminedUpgrade<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipCallCoordinatorWithUpgrade
    {
        WINRT_IMPL_AUTO(void) RequestOutgoingUpgradeToVideoCall(winrt::guid const& callUpgradeGuid, param::hstring const& context, param::hstring const& contactName, param::hstring const& serviceName, winrt::Windows::Phone::Networking::Voip::VoipPhoneCall& call) const;
        WINRT_IMPL_AUTO(void) RequestIncomingUpgradeToVideoCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, winrt::Windows::Foundation::Uri const& contactImage, param::hstring const& serviceName, winrt::Windows::Foundation::Uri const& brandingImage, param::hstring const& callDetails, winrt::Windows::Foundation::Uri const& ringtone, winrt::Windows::Foundation::TimeSpan const& ringTimeout, winrt::Windows::Phone::Networking::Voip::VoipPhoneCall& call) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithUpgrade>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipCallCoordinatorWithUpgrade<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipOperationType) Type() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipOperation>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipOperationsManager
    {
        WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::IVoipOperation) GetNextOperation() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipOperationsManager>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipOperationsManager<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipPhoneCall
    {
        WINRT_IMPL_AUTO(winrt::event_token) EndRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> const& handler) const;
        using EndRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>::remove_EndRequested>;
        [[nodiscard]] EndRequested_revoker EndRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) EndRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) HoldRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> const& handler) const;
        using HoldRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>::remove_HoldRequested>;
        [[nodiscard]] HoldRequested_revoker HoldRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) HoldRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ResumeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> const& handler) const;
        using ResumeRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>::remove_ResumeRequested>;
        [[nodiscard]] ResumeRequested_revoker ResumeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallStateChangeEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ResumeRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AnswerRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallAnswerEventArgs> const& acceptHandler) const;
        using AnswerRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>::remove_AnswerRequested>;
        [[nodiscard]] AnswerRequested_revoker AnswerRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallAnswerEventArgs> const& acceptHandler) const;
        WINRT_IMPL_AUTO(void) AnswerRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) RejectRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallRejectEventArgs> const& rejectHandler) const;
        using RejectRequested_revoker = impl::event_revoker<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall, &impl::abi_t<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>::remove_RejectRequested>;
        [[nodiscard]] RejectRequested_revoker RejectRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Phone::Networking::Voip::VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::CallRejectEventArgs> const& rejectHandler) const;
        WINRT_IMPL_AUTO(void) RejectRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) NotifyCallHeld() const;
        WINRT_IMPL_AUTO(void) NotifyCallActive() const;
        WINRT_IMPL_AUTO(void) NotifyCallEnded() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContactName() const;
        WINRT_IMPL_AUTO(void) ContactName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) StartTime() const;
        WINRT_IMPL_AUTO(void) StartTime(winrt::Windows::Foundation::DateTime const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Phone::Networking::Voip::VoipCallMedia) CallMedia() const;
        WINRT_IMPL_AUTO(void) CallMedia(winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& value) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipPhoneCall<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipPhoneCall2
    {
        WINRT_IMPL_AUTO(void) TryShowAppUI() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipPhoneCall2<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipPhoneCall3
    {
        WINRT_IMPL_AUTO(void) NotifyCallAccepted(winrt::Windows::Phone::Networking::Voip::VoipCallMedia const& media) const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipPhoneCall3<D>;
    };
    template <typename D>
    struct consume_Windows_Phone_Networking_Voip_IVoipPhoneCallReady
    {
        WINRT_IMPL_AUTO(void) NotifyCallReady() const;
    };
    template <> struct consume<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCallReady>
    {
        template <typename D> using type = consume_Windows_Phone_Networking_Voip_IVoipPhoneCallReady<D>;
    };
}
#endif
