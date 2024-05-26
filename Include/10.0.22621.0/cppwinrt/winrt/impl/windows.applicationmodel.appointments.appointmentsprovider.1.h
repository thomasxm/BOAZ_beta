// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Appointments_AppointmentsProvider_1_H
#define WINRT_Windows_ApplicationModel_Appointments_AppointmentsProvider_1_H
#include "winrt/impl/Windows.ApplicationModel.Appointments.AppointmentsProvider.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider
{
    struct __declspec(empty_bases) IAddAppointmentOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAddAppointmentOperation>
    {
        IAddAppointmentOperation(std::nullptr_t = nullptr) noexcept {}
        IAddAppointmentOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppointmentsProviderLaunchActionVerbsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppointmentsProviderLaunchActionVerbsStatics>
    {
        IAppointmentsProviderLaunchActionVerbsStatics(std::nullptr_t = nullptr) noexcept {}
        IAppointmentsProviderLaunchActionVerbsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppointmentsProviderLaunchActionVerbsStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppointmentsProviderLaunchActionVerbsStatics2>
    {
        IAppointmentsProviderLaunchActionVerbsStatics2(std::nullptr_t = nullptr) noexcept {}
        IAppointmentsProviderLaunchActionVerbsStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoveAppointmentOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoveAppointmentOperation>
    {
        IRemoveAppointmentOperation(std::nullptr_t = nullptr) noexcept {}
        IRemoveAppointmentOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IReplaceAppointmentOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IReplaceAppointmentOperation>
    {
        IReplaceAppointmentOperation(std::nullptr_t = nullptr) noexcept {}
        IReplaceAppointmentOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
