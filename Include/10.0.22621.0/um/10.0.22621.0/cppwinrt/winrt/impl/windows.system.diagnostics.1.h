// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Diagnostics_1_H
#define WINRT_Windows_System_Diagnostics_1_H
#include "winrt/impl/Windows.System.Diagnostics.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics
{
    struct __declspec(empty_bases) IDiagnosticActionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDiagnosticActionResult>
    {
        IDiagnosticActionResult(std::nullptr_t = nullptr) noexcept {}
        IDiagnosticActionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDiagnosticInvoker :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDiagnosticInvoker>
    {
        IDiagnosticInvoker(std::nullptr_t = nullptr) noexcept {}
        IDiagnosticInvoker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDiagnosticInvoker2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDiagnosticInvoker2>
    {
        IDiagnosticInvoker2(std::nullptr_t = nullptr) noexcept {}
        IDiagnosticInvoker2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDiagnosticInvokerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDiagnosticInvokerStatics>
    {
        IDiagnosticInvokerStatics(std::nullptr_t = nullptr) noexcept {}
        IDiagnosticInvokerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessCpuUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessCpuUsage>
    {
        IProcessCpuUsage(std::nullptr_t = nullptr) noexcept {}
        IProcessCpuUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessCpuUsageReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessCpuUsageReport>
    {
        IProcessCpuUsageReport(std::nullptr_t = nullptr) noexcept {}
        IProcessCpuUsageReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessDiagnosticInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessDiagnosticInfo>
    {
        IProcessDiagnosticInfo(std::nullptr_t = nullptr) noexcept {}
        IProcessDiagnosticInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessDiagnosticInfo2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessDiagnosticInfo2>
    {
        IProcessDiagnosticInfo2(std::nullptr_t = nullptr) noexcept {}
        IProcessDiagnosticInfo2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessDiagnosticInfoStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessDiagnosticInfoStatics>
    {
        IProcessDiagnosticInfoStatics(std::nullptr_t = nullptr) noexcept {}
        IProcessDiagnosticInfoStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessDiagnosticInfoStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessDiagnosticInfoStatics2>
    {
        IProcessDiagnosticInfoStatics2(std::nullptr_t = nullptr) noexcept {}
        IProcessDiagnosticInfoStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessDiskUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessDiskUsage>
    {
        IProcessDiskUsage(std::nullptr_t = nullptr) noexcept {}
        IProcessDiskUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessDiskUsageReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessDiskUsageReport>
    {
        IProcessDiskUsageReport(std::nullptr_t = nullptr) noexcept {}
        IProcessDiskUsageReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessMemoryUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessMemoryUsage>
    {
        IProcessMemoryUsage(std::nullptr_t = nullptr) noexcept {}
        IProcessMemoryUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IProcessMemoryUsageReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IProcessMemoryUsageReport>
    {
        IProcessMemoryUsageReport(std::nullptr_t = nullptr) noexcept {}
        IProcessMemoryUsageReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemCpuUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemCpuUsage>
    {
        ISystemCpuUsage(std::nullptr_t = nullptr) noexcept {}
        ISystemCpuUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemCpuUsageReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemCpuUsageReport>
    {
        ISystemCpuUsageReport(std::nullptr_t = nullptr) noexcept {}
        ISystemCpuUsageReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemDiagnosticInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemDiagnosticInfo>
    {
        ISystemDiagnosticInfo(std::nullptr_t = nullptr) noexcept {}
        ISystemDiagnosticInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemDiagnosticInfoStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemDiagnosticInfoStatics>
    {
        ISystemDiagnosticInfoStatics(std::nullptr_t = nullptr) noexcept {}
        ISystemDiagnosticInfoStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemDiagnosticInfoStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemDiagnosticInfoStatics2>
    {
        ISystemDiagnosticInfoStatics2(std::nullptr_t = nullptr) noexcept {}
        ISystemDiagnosticInfoStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemMemoryUsage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemMemoryUsage>
    {
        ISystemMemoryUsage(std::nullptr_t = nullptr) noexcept {}
        ISystemMemoryUsage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemMemoryUsageReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemMemoryUsageReport>
    {
        ISystemMemoryUsageReport(std::nullptr_t = nullptr) noexcept {}
        ISystemMemoryUsageReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
