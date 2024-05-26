// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_DragDrop_Core_2_H
#define WINRT_Windows_ApplicationModel_DataTransfer_DragDrop_Core_2_H
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.DragDrop.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core
{
    struct __declspec(empty_bases) CoreDragDropManager : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragDropManager
    {
        CoreDragDropManager(std::nullptr_t) noexcept {}
        CoreDragDropManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragDropManager(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) CoreDragInfo : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragInfo,
        impl::require<CoreDragInfo, winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragInfo2>
    {
        CoreDragInfo(std::nullptr_t) noexcept {}
        CoreDragInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreDragOperation : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragOperation,
        impl::require<CoreDragOperation, winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragOperation2>
    {
        CoreDragOperation(std::nullptr_t) noexcept {}
        CoreDragOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragOperation(ptr, take_ownership_from_abi) {}
        CoreDragOperation();
    };
    struct __declspec(empty_bases) CoreDragUIOverride : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragUIOverride
    {
        CoreDragUIOverride(std::nullptr_t) noexcept {}
        CoreDragUIOverride(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDragUIOverride(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreDropOperationTargetRequestedEventArgs : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDropOperationTargetRequestedEventArgs
    {
        CoreDropOperationTargetRequestedEventArgs(std::nullptr_t) noexcept {}
        CoreDropOperationTargetRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::DragDrop::Core::ICoreDropOperationTargetRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
