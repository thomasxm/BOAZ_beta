// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_UIAutomation_Core_2_H
#define WINRT_Windows_UI_UIAutomation_Core_2_H
#include "winrt/impl/Windows.UI.UIAutomation.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::UIAutomation::Core
{
    struct AutomationAnnotationTypeRegistration
    {
        int32_t LocalId;
    };
    inline bool operator==(AutomationAnnotationTypeRegistration const& left, AutomationAnnotationTypeRegistration const& right) noexcept
    {
        return left.LocalId == right.LocalId;
    }
    inline bool operator!=(AutomationAnnotationTypeRegistration const& left, AutomationAnnotationTypeRegistration const& right) noexcept
    {
        return !(left == right);
    }
    struct AutomationRemoteOperationOperandId
    {
        int32_t Value;
    };
    inline bool operator==(AutomationRemoteOperationOperandId const& left, AutomationRemoteOperationOperandId const& right) noexcept
    {
        return left.Value == right.Value;
    }
    inline bool operator!=(AutomationRemoteOperationOperandId const& left, AutomationRemoteOperationOperandId const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) AutomationRemoteOperationResult : winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult
    {
        AutomationRemoteOperationResult(std::nullptr_t) noexcept {}
        AutomationRemoteOperationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult(ptr, take_ownership_from_abi) {}
    };
    struct CoreAutomationRegistrar
    {
        CoreAutomationRegistrar() = delete;
        static auto RegisterAnnotationType(winrt::guid const& guid);
        static auto UnregisterAnnotationType(winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration const& registration);
    };
    struct __declspec(empty_bases) CoreAutomationRemoteOperation : winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation,
        impl::require<CoreAutomationRemoteOperation, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation2>
    {
        CoreAutomationRemoteOperation(std::nullptr_t) noexcept {}
        CoreAutomationRemoteOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation(ptr, take_ownership_from_abi) {}
        CoreAutomationRemoteOperation();
    };
    struct __declspec(empty_bases) CoreAutomationRemoteOperationContext : winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext
    {
        CoreAutomationRemoteOperationContext(std::nullptr_t) noexcept {}
        CoreAutomationRemoteOperationContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RemoteAutomationClientSession : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession
    {
        RemoteAutomationClientSession(std::nullptr_t) noexcept {}
        RemoteAutomationClientSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession(ptr, take_ownership_from_abi) {}
        explicit RemoteAutomationClientSession(param::hstring const& name);
        RemoteAutomationClientSession(param::hstring const& name, winrt::guid const& sessionId);
    };
    struct __declspec(empty_bases) RemoteAutomationConnectionRequestedEventArgs : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs
    {
        RemoteAutomationConnectionRequestedEventArgs(std::nullptr_t) noexcept {}
        RemoteAutomationConnectionRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RemoteAutomationDisconnectedEventArgs : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationDisconnectedEventArgs
    {
        RemoteAutomationDisconnectedEventArgs(std::nullptr_t) noexcept {}
        RemoteAutomationDisconnectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationDisconnectedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct RemoteAutomationServer
    {
        RemoteAutomationServer() = delete;
        static auto ReportSession(winrt::guid const& sessionId);
    };
    struct __declspec(empty_bases) RemoteAutomationWindow : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow
    {
        RemoteAutomationWindow(std::nullptr_t) noexcept {}
        RemoteAutomationWindow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow(ptr, take_ownership_from_abi) {}
    };
}
#endif
