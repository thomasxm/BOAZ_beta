// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserDataTasks_2_H
#define WINRT_Windows_ApplicationModel_UserDataTasks_2_H
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataTasks.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataTasks
{
    struct __declspec(empty_bases) UserDataTask : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTask
    {
        UserDataTask(std::nullptr_t) noexcept {}
        UserDataTask(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTask(ptr, take_ownership_from_abi) {}
        UserDataTask();
    };
    struct __declspec(empty_bases) UserDataTaskBatch : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch
    {
        UserDataTaskBatch(std::nullptr_t) noexcept {}
        UserDataTaskBatch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataTaskList : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskList
    {
        UserDataTaskList(std::nullptr_t) noexcept {}
        UserDataTaskList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskList(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataTaskListLimitedWriteOperations : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations
    {
        UserDataTaskListLimitedWriteOperations(std::nullptr_t) noexcept {}
        UserDataTaskListLimitedWriteOperations(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataTaskListSyncManager : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager
    {
        UserDataTaskListSyncManager(std::nullptr_t) noexcept {}
        UserDataTaskListSyncManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataTaskManager : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager
    {
        UserDataTaskManager(std::nullptr_t) noexcept {}
        UserDataTaskManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) UserDataTaskQueryOptions : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions
    {
        UserDataTaskQueryOptions(std::nullptr_t) noexcept {}
        UserDataTaskQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions(ptr, take_ownership_from_abi) {}
        UserDataTaskQueryOptions();
    };
    struct __declspec(empty_bases) UserDataTaskReader : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader
    {
        UserDataTaskReader(std::nullptr_t) noexcept {}
        UserDataTaskReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UserDataTaskRecurrenceProperties : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties
    {
        UserDataTaskRecurrenceProperties(std::nullptr_t) noexcept {}
        UserDataTaskRecurrenceProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties(ptr, take_ownership_from_abi) {}
        UserDataTaskRecurrenceProperties();
    };
    struct __declspec(empty_bases) UserDataTaskRegenerationProperties : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties
    {
        UserDataTaskRegenerationProperties(std::nullptr_t) noexcept {}
        UserDataTaskRegenerationProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties(ptr, take_ownership_from_abi) {}
        UserDataTaskRegenerationProperties();
    };
    struct __declspec(empty_bases) UserDataTaskStore : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore
    {
        UserDataTaskStore(std::nullptr_t) noexcept {}
        UserDataTaskStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore(ptr, take_ownership_from_abi) {}
    };
}
#endif
