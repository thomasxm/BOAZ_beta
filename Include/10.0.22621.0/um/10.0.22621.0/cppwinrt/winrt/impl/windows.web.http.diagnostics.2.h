// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_Http_Diagnostics_2_H
#define WINRT_Windows_Web_Http_Diagnostics_2_H
#include "winrt/impl/Windows.System.Diagnostics.1.h"
#include "winrt/impl/Windows.Web.Http.Diagnostics.1.h"
WINRT_EXPORT namespace winrt::Windows::Web::Http::Diagnostics
{
    struct __declspec(empty_bases) HttpDiagnosticProvider : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider
    {
        HttpDiagnosticProvider(std::nullptr_t) noexcept {}
        HttpDiagnosticProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider(ptr, take_ownership_from_abi) {}
        static auto CreateFromProcessDiagnosticInfo(winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo const& processDiagnosticInfo);
    };
    struct __declspec(empty_bases) HttpDiagnosticProviderRequestResponseCompletedEventArgs : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs
    {
        HttpDiagnosticProviderRequestResponseCompletedEventArgs(std::nullptr_t) noexcept {}
        HttpDiagnosticProviderRequestResponseCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HttpDiagnosticProviderRequestResponseTimestamps : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps
    {
        HttpDiagnosticProviderRequestResponseTimestamps(std::nullptr_t) noexcept {}
        HttpDiagnosticProviderRequestResponseTimestamps(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HttpDiagnosticProviderRequestSentEventArgs : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs
    {
        HttpDiagnosticProviderRequestSentEventArgs(std::nullptr_t) noexcept {}
        HttpDiagnosticProviderRequestSentEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HttpDiagnosticProviderResponseReceivedEventArgs : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs
    {
        HttpDiagnosticProviderResponseReceivedEventArgs(std::nullptr_t) noexcept {}
        HttpDiagnosticProviderResponseReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HttpDiagnosticSourceLocation : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation
    {
        HttpDiagnosticSourceLocation(std::nullptr_t) noexcept {}
        HttpDiagnosticSourceLocation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation(ptr, take_ownership_from_abi) {}
    };
}
#endif
