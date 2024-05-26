// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserDataTasks_1_H
#define WINRT_Windows_ApplicationModel_UserDataTasks_1_H
#include "winrt/impl/Windows.ApplicationModel.UserDataTasks.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataTasks
{
    struct __declspec(empty_bases) IUserDataTask :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTask>
    {
        IUserDataTask(std::nullptr_t = nullptr) noexcept {}
        IUserDataTask(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskBatch :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskBatch>
    {
        IUserDataTaskBatch(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskBatch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskList>
    {
        IUserDataTaskList(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskListLimitedWriteOperations :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskListLimitedWriteOperations>
    {
        IUserDataTaskListLimitedWriteOperations(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskListLimitedWriteOperations(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskListSyncManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskListSyncManager>
    {
        IUserDataTaskListSyncManager(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskListSyncManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskManager>
    {
        IUserDataTaskManager(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskManagerStatics>
    {
        IUserDataTaskManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskQueryOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskQueryOptions>
    {
        IUserDataTaskQueryOptions(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskReader>
    {
        IUserDataTaskReader(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskRecurrenceProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskRecurrenceProperties>
    {
        IUserDataTaskRecurrenceProperties(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskRecurrenceProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskRegenerationProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskRegenerationProperties>
    {
        IUserDataTaskRegenerationProperties(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskRegenerationProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUserDataTaskStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUserDataTaskStore>
    {
        IUserDataTaskStore(std::nullptr_t = nullptr) noexcept {}
        IUserDataTaskStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
