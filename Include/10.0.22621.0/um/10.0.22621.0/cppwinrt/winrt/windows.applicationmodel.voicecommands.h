// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_VoiceCommands_H
#define WINRT_Windows_ApplicationModel_VoiceCommands_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Media.SpeechRecognition.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.ApplicationModel.VoiceCommands.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommand<D>::CommandName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand)->get_CommandName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommand<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommand<D>::SpeechRecognitionResult() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand)->get_SpeechRecognitionResult(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletionReason) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandCompletedEventArgs<D>::Reason() const
    {
        winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletionReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandConfirmationResult<D>::Confirmed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult)->get_Confirmed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::TextLine1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_TextLine1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::TextLine1(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_TextLine1(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::TextLine2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_TextLine2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::TextLine2(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_TextLine2(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::TextLine3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_TextLine3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::TextLine3(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_TextLine3(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::Image() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_Image(&value));
        return winrt::Windows::Storage::IStorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::Image(winrt::Windows::Storage::IStorageFile const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_Image(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::AppContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_AppContext(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::AppContext(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_AppContext(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::AppLaunchArgument() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_AppLaunchArgument(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::AppLaunchArgument(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_AppLaunchArgument(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::ContentTileType() const
    {
        winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->get_ContentTileType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandContentTile<D>::ContentTileType(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile)->put_ContentTileType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinition<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinition<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinition<D>::SetPhraseListAsync(param::hstring const& phraseListName, param::async_iterable<hstring> const& phraseList) const
    {
        void* updateAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition)->SetPhraseListAsync(*(void**)(&phraseListName), *(void**)(&phraseList), &updateAction));
        return winrt::Windows::Foundation::IAsyncAction{ updateAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinitionManagerStatics<D>::InstallCommandDefinitionsFromStorageFileAsync(winrt::Windows::Storage::StorageFile const& file) const
    {
        void* installAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics)->InstallCommandDefinitionsFromStorageFileAsync(*(void**)(&file), &installAction));
        return winrt::Windows::Foundation::IAsyncAction{ installAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDefinitionManagerStatics<D>::InstalledCommandDefinitions() const
    {
        void* voiceCommandDefinitions{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics)->get_InstalledCommandDefinitions(&voiceCommandDefinitions));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>{ voiceCommandDefinitions, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandDisambiguationResult<D>::SelectedItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult)->get_SelectedItem(&value));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->get_Message(&value));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::Message(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->put_Message(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::RepeatMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->get_RepeatMessage(&value));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::RepeatMessage(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->put_RepeatMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::AppLaunchArgument() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->get_AppLaunchArgument(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::AppLaunchArgument(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->put_AppLaunchArgument(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponse<D>::VoiceCommandContentTiles() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse)->get_VoiceCommandContentTiles(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics<D>::MaxSupportedVoiceCommandContentTiles() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics)->get_MaxSupportedVoiceCommandContentTiles(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics<D>::CreateResponse(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& userMessage) const
    {
        void* response{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics)->CreateResponse(*(void**)(&userMessage), &response));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse{ response, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics<D>::CreateResponse(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, param::iterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const& contentTiles) const
    {
        void* response{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics)->CreateResponseWithTiles(*(void**)(&message), *(void**)(&contentTiles), &response));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse{ response, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics<D>::CreateResponseForPrompt(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& repeatMessage) const
    {
        void* response{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics)->CreateResponseForPrompt(*(void**)(&message), *(void**)(&repeatMessage), &response));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse{ response, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandResponseStatics<D>::CreateResponseForPrompt(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& repeatMessage, param::iterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const& contentTiles) const
    {
        void* response{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics)->CreateResponseForPromptWithTiles(*(void**)(&message), *(void**)(&repeatMessage), *(void**)(&contentTiles), &response));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse{ response, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand>) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::GetVoiceCommandAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->GetVoiceCommandAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult>) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::RequestConfirmationAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->RequestConfirmationAsync(*(void**)(&response), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult>) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::RequestDisambiguationAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->RequestDisambiguationAsync(*(void**)(&response), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::ReportProgressAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->ReportProgressAsync(*(void**)(&response), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::ReportSuccessAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->ReportSuccessAsync(*(void**)(&response), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::ReportFailureAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->ReportFailureAsync(*(void**)(&response), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::RequestAppLaunchAsync(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const& response) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->RequestAppLaunchAsync(*(void**)(&response), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::Language() const
    {
        void* language{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->get_Language(&language));
        return winrt::Windows::Globalization::Language{ language, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::VoiceCommandCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->add_VoiceCommandCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::VoiceCommandCompleted_revoker consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::VoiceCommandCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, VoiceCommandCompleted_revoker>(this, VoiceCommandCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnection<D>::VoiceCommandCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection)->remove_VoiceCommandCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandServiceConnectionStatics<D>::FromAppServiceTriggerDetails(winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails const& triggerDetails) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics)->FromAppServiceTriggerDetails(*(void**)(&triggerDetails), &value));
        return winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandUserMessage<D>::DisplayMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage)->get_DisplayMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandUserMessage<D>::DisplayMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage)->put_DisplayMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandUserMessage<D>::SpokenMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage)->get_SpokenMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_VoiceCommands_IVoiceCommandUserMessage<D>::SpokenMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage)->put_SpokenMessage(*(void**)(&value)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand>
    {
        int32_t __stdcall get_CommandName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CommandName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeechRecognitionResult(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>(this->shim().SpeechRecognitionResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletionReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult>
    {
        int32_t __stdcall get_Confirmed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Confirmed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextLine1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TextLine1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextLine1(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextLine1(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextLine2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TextLine2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextLine2(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextLine2(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextLine3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TextLine3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextLine3(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextLine3(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Image(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::IStorageFile>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Image(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Image(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().AppContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppContext(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppContext(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppLaunchArgument(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppLaunchArgument());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppLaunchArgument(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppLaunchArgument(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTileType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType>(this->shim().ContentTileType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTileType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTileType(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTileType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition>
    {
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPhraseListAsync(void* phraseListName, void* phraseList, void** updateAction) noexcept final try
        {
            clear_abi(updateAction);
            typename D::abi_guard guard(this->shim());
            *updateAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetPhraseListAsync(*reinterpret_cast<hstring const*>(&phraseListName), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&phraseList)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics>
    {
        int32_t __stdcall InstallCommandDefinitionsFromStorageFileAsync(void* file, void** installAction) noexcept final try
        {
            clear_abi(installAction);
            typename D::abi_guard guard(this->shim());
            *installAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().InstallCommandDefinitionsFromStorageFileAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstalledCommandDefinitions(void** voiceCommandDefinitions) noexcept final try
        {
            clear_abi(voiceCommandDefinitions);
            typename D::abi_guard guard(this->shim());
            *voiceCommandDefinitions = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>>(this->shim().InstalledCommandDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult>
    {
        int32_t __stdcall get_SelectedItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>(this->shim().SelectedItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Message(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Message(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RepeatMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage>(this->shim().RepeatMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RepeatMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RepeatMessage(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppLaunchArgument(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppLaunchArgument());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppLaunchArgument(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppLaunchArgument(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VoiceCommandContentTiles(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile>>(this->shim().VoiceCommandContentTiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics>
    {
        int32_t __stdcall get_MaxSupportedVoiceCommandContentTiles(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxSupportedVoiceCommandContentTiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResponse(void* userMessage, void** response) noexcept final try
        {
            clear_abi(response);
            typename D::abi_guard guard(this->shim());
            *response = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse>(this->shim().CreateResponse(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&userMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResponseWithTiles(void* message, void* contentTiles, void** response) noexcept final try
        {
            clear_abi(response);
            typename D::abi_guard guard(this->shim());
            *response = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse>(this->shim().CreateResponse(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&message), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const*>(&contentTiles)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResponseForPrompt(void* message, void* repeatMessage, void** response) noexcept final try
        {
            clear_abi(response);
            typename D::abi_guard guard(this->shim());
            *response = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse>(this->shim().CreateResponseForPrompt(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&message), *reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&repeatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResponseForPromptWithTiles(void* message, void* repeatMessage, void* contentTiles, void** response) noexcept final try
        {
            clear_abi(response);
            typename D::abi_guard guard(this->shim());
            *response = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse>(this->shim().CreateResponseForPrompt(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&message), *reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const*>(&repeatMessage), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const*>(&contentTiles)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection>
    {
        int32_t __stdcall GetVoiceCommandAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand>>(this->shim().GetVoiceCommandAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestConfirmationAsync(void* response, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult>>(this->shim().RequestConfirmationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestDisambiguationAsync(void* response, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult>>(this->shim().RequestDisambiguationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportProgressAsync(void* response, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportProgressAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportSuccessAsync(void* response, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportSuccessAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailureAsync(void* response, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailureAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAppLaunchAsync(void* response, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RequestAppLaunchAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** language) noexcept final try
        {
            clear_abi(language);
            typename D::abi_guard guard(this->shim());
            *language = detach_from<winrt::Windows::Globalization::Language>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_VoiceCommandCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VoiceCommandCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VoiceCommandCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VoiceCommandCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics>
    {
        int32_t __stdcall FromAppServiceTriggerDetails(void* triggerDetails, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection>(this->shim().FromAppServiceTriggerDetails(*reinterpret_cast<winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails const*>(&triggerDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage> : produce_base<D, winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage>
    {
        int32_t __stdcall get_DisplayMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpokenMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SpokenMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpokenMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpokenMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::VoiceCommands
{
    inline VoiceCommandContentTile::VoiceCommandContentTile() :
        VoiceCommandContentTile(impl::call_factory_cast<VoiceCommandContentTile(*)(winrt::Windows::Foundation::IActivationFactory const&), VoiceCommandContentTile>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VoiceCommandContentTile>(); }))
    {
    }
    inline auto VoiceCommandDefinitionManager::InstallCommandDefinitionsFromStorageFileAsync(winrt::Windows::Storage::StorageFile const& file)
    {
        return impl::call_factory<VoiceCommandDefinitionManager, IVoiceCommandDefinitionManagerStatics>([&](IVoiceCommandDefinitionManagerStatics const& f) { return f.InstallCommandDefinitionsFromStorageFileAsync(file); });
    }
    inline auto VoiceCommandDefinitionManager::InstalledCommandDefinitions()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition>(*)(IVoiceCommandDefinitionManagerStatics const&), VoiceCommandDefinitionManager, IVoiceCommandDefinitionManagerStatics>([](IVoiceCommandDefinitionManagerStatics const& f) { return f.InstalledCommandDefinitions(); });
    }
    inline auto VoiceCommandResponse::MaxSupportedVoiceCommandContentTiles()
    {
        return impl::call_factory_cast<uint32_t(*)(IVoiceCommandResponseStatics const&), VoiceCommandResponse, IVoiceCommandResponseStatics>([](IVoiceCommandResponseStatics const& f) { return f.MaxSupportedVoiceCommandContentTiles(); });
    }
    inline auto VoiceCommandResponse::CreateResponse(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& userMessage)
    {
        return impl::call_factory<VoiceCommandResponse, IVoiceCommandResponseStatics>([&](IVoiceCommandResponseStatics const& f) { return f.CreateResponse(userMessage); });
    }
    inline auto VoiceCommandResponse::CreateResponse(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, param::iterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const& contentTiles)
    {
        return impl::call_factory<VoiceCommandResponse, IVoiceCommandResponseStatics>([&](IVoiceCommandResponseStatics const& f) { return f.CreateResponse(message, contentTiles); });
    }
    inline auto VoiceCommandResponse::CreateResponseForPrompt(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& repeatMessage)
    {
        return impl::call_factory<VoiceCommandResponse, IVoiceCommandResponseStatics>([&](IVoiceCommandResponseStatics const& f) { return f.CreateResponseForPrompt(message, repeatMessage); });
    }
    inline auto VoiceCommandResponse::CreateResponseForPrompt(winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& message, winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage const& repeatMessage, param::iterable<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> const& contentTiles)
    {
        return impl::call_factory<VoiceCommandResponse, IVoiceCommandResponseStatics>([&](IVoiceCommandResponseStatics const& f) { return f.CreateResponseForPrompt(message, repeatMessage, contentTiles); });
    }
    inline auto VoiceCommandServiceConnection::FromAppServiceTriggerDetails(winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails const& triggerDetails)
    {
        return impl::call_factory<VoiceCommandServiceConnection, IVoiceCommandServiceConnectionStatics>([&](IVoiceCommandServiceConnectionStatics const& f) { return f.FromAppServiceTriggerDetails(triggerDetails); });
    }
    inline VoiceCommandUserMessage::VoiceCommandUserMessage() :
        VoiceCommandUserMessage(impl::call_factory_cast<VoiceCommandUserMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), VoiceCommandUserMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VoiceCommandUserMessage>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandConfirmationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandContentTile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDefinitionManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandDisambiguationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandResponseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandServiceConnectionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::IVoiceCommandUserMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandConfirmationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandContentTile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDefinitionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandDisambiguationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandResponse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandServiceConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::VoiceCommands::VoiceCommandUserMessage> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
