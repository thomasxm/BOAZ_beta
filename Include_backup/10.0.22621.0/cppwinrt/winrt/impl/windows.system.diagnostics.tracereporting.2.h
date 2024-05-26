// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Diagnostics_TraceReporting_2_H
#define WINRT_Windows_System_Diagnostics_TraceReporting_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.System.Diagnostics.TraceReporting.1.h"
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::TraceReporting
{
    struct PlatformDiagnosticActions
    {
        PlatformDiagnosticActions() = delete;
        static auto IsScenarioEnabled(winrt::guid const& scenarioId);
        static auto TryEscalateScenario(winrt::guid const& scenarioId, winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const& escalationType, param::hstring const& outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, param::map_view<hstring, hstring> const& triggers);
        static auto DownloadLatestSettingsForNamespace(param::hstring const& partner, param::hstring const& feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery);
        static auto GetActiveScenarioList();
        static auto ForceUpload(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const& latency, bool uploadOverCostedNetwork, bool uploadOverBattery);
        static auto IsTraceRunning(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType, winrt::guid const& scenarioId, uint64_t traceProfileHash);
        static auto GetActiveTraceRuntime(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType);
        static auto GetKnownTraceList(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType);
    };
    struct __declspec(empty_bases) PlatformDiagnosticTraceInfo : winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo
    {
        PlatformDiagnosticTraceInfo(std::nullptr_t) noexcept {}
        PlatformDiagnosticTraceInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PlatformDiagnosticTraceRuntimeInfo : winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo
    {
        PlatformDiagnosticTraceRuntimeInfo(std::nullptr_t) noexcept {}
        PlatformDiagnosticTraceRuntimeInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo(ptr, take_ownership_from_abi) {}
    };
}
#endif
