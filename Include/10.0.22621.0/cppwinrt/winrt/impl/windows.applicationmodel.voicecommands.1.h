// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_VoiceCommands_1_H
#define WINRT_Windows_ApplicationModel_VoiceCommands_1_H
#include "winrt/impl/Windows.ApplicationModel.VoiceCommands.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::VoiceCommands
{
    struct __declspec(empty_bases) IVoiceCommand :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommand>
    {
        IVoiceCommand(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandCompletedEventArgs>
    {
        IVoiceCommandCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandConfirmationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandConfirmationResult>
    {
        IVoiceCommandConfirmationResult(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandConfirmationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandContentTile :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandContentTile>
    {
        IVoiceCommandContentTile(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandContentTile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandDefinition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandDefinition>
    {
        IVoiceCommandDefinition(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandDefinition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandDefinitionManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandDefinitionManagerStatics>
    {
        IVoiceCommandDefinitionManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandDefinitionManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandDisambiguationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandDisambiguationResult>
    {
        IVoiceCommandDisambiguationResult(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandDisambiguationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandResponse :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandResponse>
    {
        IVoiceCommandResponse(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandResponse(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandResponseStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandResponseStatics>
    {
        IVoiceCommandResponseStatics(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandResponseStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandServiceConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandServiceConnection>
    {
        IVoiceCommandServiceConnection(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandServiceConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandServiceConnectionStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandServiceConnectionStatics>
    {
        IVoiceCommandServiceConnectionStatics(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandServiceConnectionStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceCommandUserMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceCommandUserMessage>
    {
        IVoiceCommandUserMessage(std::nullptr_t = nullptr) noexcept {}
        IVoiceCommandUserMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
