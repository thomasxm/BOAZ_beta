// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_VoiceCommands_0_H
#define WINRT_Windows_ApplicationModel_VoiceCommands_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppService
{
    struct AppServiceTriggerDetails;
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
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Globalization
{
    struct Language;
}
WINRT_EXPORT namespace winrt::Windows::Media::SpeechRecognition
{
    struct SpeechRecognitionResult;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
    struct StorageFile;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::VoiceCommands
{
    enum class VoiceCommandCompletionReason : int32_t
    {
        Unknown = 0,
        CommunicationFailed = 1,
        ResourceLimitsExceeded = 2,
        Canceled = 3,
        TimeoutExceeded = 4,
        AppLaunched = 5,
        Completed = 6,
    };
    enum class VoiceCommandContentTileType : int32_t
    {
        TitleOnly = 0,
        TitleWithText = 1,
        TitleWith68x68Icon = 2,
        TitleWith68x68IconAndText = 3,
        TitleWith68x92Icon = 4,
        TitleWith68x92IconAndText = 5,
        TitleWith280x140Icon = 6,
        TitleWith280x140IconAndText = 7,
    };
    struct IVoiceCommand;
    struct IVoiceCommandCompletedEventArgs;
    struct IVoiceCommandConfirmationResult;
    struct IVoiceCommandContentTile;
    struct IVoiceCommandDefinition;
    struct IVoiceCommandDefinitionManagerStatics;
    struct IVoiceCommandDisambiguationResult;
    struct IVoiceCommandResponse;
    struct IVoiceCommandResponseStatics;
    struct IVoiceCommandServiceConnection;
    struct IVoiceCommandServiceConnectionStatics;
    struct IVoiceCommandUserMessage;
    struct VoiceCommand;
    struct VoiceCommandCompletedEventArgs;
    struct VoiceCommandConfirmationResult;
    struct VoiceCommandContentTile;
    struct VoiceCommandDefinition;
    struct VoiceCommandDefinitionManager;
    struct VoiceCommandDisambiguationResult;
    struct VoiceCommandResponse;
    struct VoiceCommandServiceConnection;
    struct VoiceCommandUserMessage;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinitionManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletionReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommand";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandConfirmationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandContentTile";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandDefinition";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinitionManager> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandDefinitionManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandDisambiguationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandResponse";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandServiceConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandUserMessage";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletionReason> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandCompletionReason";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType> = L"Windows.ApplicationModel.VoiceCommands.VoiceCommandContentTileType";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommand";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandConfirmationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandContentTile";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandDefinition";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandDefinitionManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandDisambiguationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandResponse";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandResponseStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandServiceConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandServiceConnectionStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage> = L"Windows.ApplicationModel.VoiceCommands.IVoiceCommandUserMessage";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand>{ 0x936F5273,0xEC82,0x42A6,{ 0xA5,0x5C,0xD2,0xD7,0x9E,0xC6,0xF9,0x20 } }; // 936F5273-EC82-42A6-A55C-D2D79EC6F920
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs>{ 0xC85E675D,0xFE42,0x432C,{ 0x99,0x07,0x09,0xDF,0x9F,0xCF,0x64,0xE8 } }; // C85E675D-FE42-432C-9907-09DF9FCF64E8
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult>{ 0xA022593E,0x8221,0x4526,{ 0xB0,0x83,0x84,0x09,0x72,0x26,0x22,0x47 } }; // A022593E-8221-4526-B083-840972262247
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile>{ 0x3EEFE9F0,0xB8C7,0x4C76,{ 0xA0,0xDE,0x16,0x07,0x89,0x5E,0xE3,0x27 } }; // 3EEFE9F0-B8C7-4C76-A0DE-1607895EE327
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition>{ 0x7972AAD0,0x0974,0x4979,{ 0x98,0x4B,0xCB,0x89,0x59,0xCD,0x61,0xAE } }; // 7972AAD0-0974-4979-984B-CB8959CD61AE
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics>{ 0x8FE7A69E,0x067E,0x4F16,{ 0xA1,0x8C,0x5B,0x17,0xE9,0x49,0x99,0x40 } }; // 8FE7A69E-067E-4F16-A18C-5B17E9499940
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult>{ 0xECC68CFE,0xC9AC,0x45DF,{ 0xA8,0xEA,0xFE,0xEA,0x08,0xEF,0x9C,0x5E } }; // ECC68CFE-C9AC-45DF-A8EA-FEEA08EF9C5E
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse>{ 0x0284B30E,0x8A3B,0x4CC4,{ 0xA6,0xA1,0xCA,0xD5,0xBE,0x27,0x16,0xB5 } }; // 0284B30E-8A3B-4CC4-A6A1-CAD5BE2716B5
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics>{ 0x2932F813,0x0D3B,0x49F2,{ 0x96,0xDD,0x62,0x50,0x19,0xBD,0x3B,0x5D } }; // 2932F813-0D3B-49F2-96DD-625019BD3B5D
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection>{ 0xD894BB9F,0x21DA,0x44A4,{ 0x98,0xA2,0xFB,0x13,0x19,0x20,0xA9,0xCC } }; // D894BB9F-21DA-44A4-98A2-FB131920A9CC
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics>{ 0x370EBFFB,0x2D34,0x42DF,{ 0x87,0x70,0x07,0x4D,0x0F,0x33,0x46,0x97 } }; // 370EBFFB-2D34-42DF-8770-074D0F334697
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage>{ 0x674EB3C0,0x44F6,0x4F07,{ 0xB9,0x79,0x4C,0x72,0x3F,0xC0,0x85,0x97 } }; // 674EB3C0-44F6-4F07-B979-4C723FC08597
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage>{ using type = winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage; };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CommandName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
            virtual int32_t __stdcall get_SpeechRecognitionResult(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reason(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Confirmed(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall put_Title(void*) noexcept = 0;
            virtual int32_t __stdcall get_TextLine1(void**) noexcept = 0;
            virtual int32_t __stdcall put_TextLine1(void*) noexcept = 0;
            virtual int32_t __stdcall get_TextLine2(void**) noexcept = 0;
            virtual int32_t __stdcall put_TextLine2(void*) noexcept = 0;
            virtual int32_t __stdcall get_TextLine3(void**) noexcept = 0;
            virtual int32_t __stdcall put_TextLine3(void*) noexcept = 0;
            virtual int32_t __stdcall get_Image(void**) noexcept = 0;
            virtual int32_t __stdcall put_Image(void*) noexcept = 0;
            virtual int32_t __stdcall get_AppContext(void**) noexcept = 0;
            virtual int32_t __stdcall put_AppContext(void*) noexcept = 0;
            virtual int32_t __stdcall get_AppLaunchArgument(void**) noexcept = 0;
            virtual int32_t __stdcall put_AppLaunchArgument(void*) noexcept = 0;
            virtual int32_t __stdcall get_ContentTileType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ContentTileType(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Language(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall SetPhraseListAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall InstallCommandDefinitionsFromStorageFileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_InstalledCommandDefinitions(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SelectedItem(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
            virtual int32_t __stdcall put_Message(void*) noexcept = 0;
            virtual int32_t __stdcall get_RepeatMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_RepeatMessage(void*) noexcept = 0;
            virtual int32_t __stdcall get_AppLaunchArgument(void**) noexcept = 0;
            virtual int32_t __stdcall put_AppLaunchArgument(void*) noexcept = 0;
            virtual int32_t __stdcall get_VoiceCommandContentTiles(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MaxSupportedVoiceCommandContentTiles(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall CreateResponse(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateResponseWithTiles(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateResponseForPrompt(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateResponseForPromptWithTiles(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetVoiceCommandAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RequestConfirmationAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestDisambiguationAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportProgressAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportSuccessAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailureAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAppLaunchAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_Language(void**) noexcept = 0;
            virtual int32_t __stdcall add_VoiceCommandCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_VoiceCommandCompleted(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromAppServiceTriggerDetails(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayMessage(void*) noexcept = 0;
            virtual int32_t __stdcall get_SpokenMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_SpokenMessage(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommand
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CommandName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>) Properties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult) SpeechRecognitionResult() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommand<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletionReason) Reason() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandConfirmationResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Confirmed() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandConfirmationResult<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        WINRT_IMPL_AUTO(void) Title(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TextLine1() const;
        WINRT_IMPL_AUTO(void) TextLine1(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TextLine2() const;
        WINRT_IMPL_AUTO(void) TextLine2(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TextLine3() const;
        WINRT_IMPL_AUTO(void) TextLine3(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) Image() const;
        WINRT_IMPL_AUTO(void) Image(winrt::Windows::Storage::IStorageFile const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) AppContext() const;
        WINRT_IMPL_AUTO(void) AppContext(winrt::Windows::Foundation::IInspectable const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AppLaunchArgument() const;
        WINRT_IMPL_AUTO(void) AppLaunchArgument(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType) ContentTileType() const;
        WINRT_IMPL_AUTO(void) ContentTileType(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinition
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Language() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetPhraseListAsync(param::hstring const& phraseListName, param::async_iterable<hstring> const& phraseList) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinition<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinitionManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) InstallCommandDefinitionsFromStorageFileAsync(winrt::Windows::Storage::StorageFile const& file) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>) InstalledCommandDefinitions() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinitionManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDisambiguationResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile) SelectedItem() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDisambiguationResult<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage) Message() const;
        WINRT_IMPL_AUTO(void) Message(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage) RepeatMessage() const;
        WINRT_IMPL_AUTO(void) RepeatMessage(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AppLaunchArgument() const;
        WINRT_IMPL_AUTO(void) AppLaunchArgument(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>) VoiceCommandContentTiles() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxSupportedVoiceCommandContentTiles() const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) CreateResponse(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& userMessage) const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) CreateResponse(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, param::iterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const& contentTiles) const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) CreateResponseForPrompt(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& repeatMessage) const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) CreateResponseForPrompt(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& repeatMessage, param::iterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const& contentTiles) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand>) GetVoiceCommandAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult>) RequestConfirmationAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult>) RequestDisambiguationAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportProgressAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportSuccessAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailureAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) RequestAppLaunchAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) Language() const;
        WINRT_IMPL_AUTO(winrt::event_token) VoiceCommandCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> const& handler) const;
        using VoiceCommandCompleted_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection, &impl::abi_t<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection>::remove_VoiceCommandCompleted>;
        [[nodiscard]] VoiceCommandCompleted_revoker VoiceCommandCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) VoiceCommandCompleted(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnectionStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection) FromAppServiceTriggerDetails(winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails const& triggerDetails) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnectionStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandUserMessage
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayMessage() const;
        WINRT_IMPL_AUTO(void) DisplayMessage(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SpokenMessage() const;
        WINRT_IMPL_AUTO(void) SpokenMessage(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandUserMessage<D>;
    };
}
#endif
