// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Isolation_H
#define WINRT_Windows_Security_Isolation_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Isolation.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::StartProcessSilentlyAsync(param::hstring const& hostExePath, param::hstring const& arguments, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator const& activator) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->StartProcessSilentlyAsync(*(void**)(&hostExePath), *(void**)(&arguments), static_cast<int32_t>(activator), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::StartProcessSilentlyAsync(param::hstring const& hostExePath, param::hstring const& arguments, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator const& activator, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->StartProcessSilentlyWithTelemetryAsync(*(void**)(&hostExePath), *(void**)(&arguments), static_cast<int32_t>(activator), *(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::ShareFolderAsync(param::hstring const& hostFolder, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions const& requestOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->ShareFolderAsync(*(void**)(&hostFolder), *(void**)(&requestOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::ShareFolderAsync(param::hstring const& hostFolder, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions const& requestOptions, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->ShareFolderWithTelemetryAsync(*(void**)(&hostFolder), *(void**)(&requestOptions), *(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::LaunchFileWithUIAsync(param::hstring const& appExePath, param::hstring const& argumentsTemplate, param::hstring const& filePath) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->LaunchFileWithUIAsync(*(void**)(&appExePath), *(void**)(&argumentsTemplate), *(void**)(&filePath), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::LaunchFileWithUIAsync(param::hstring const& appExePath, param::hstring const& argumentsTemplate, param::hstring const& filePath, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->LaunchFileWithUIAndTelemetryAsync(*(void**)(&appExePath), *(void**)(&argumentsTemplate), *(void**)(&filePath), *(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::TerminateAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->TerminateAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::TerminateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->TerminateWithTelemetryAsync(*(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::RegisterMessageReceiver(winrt::guid const& receiverId, winrt::Windows::Security::Isolation::MessageReceivedCallback const& messageReceivedCallback) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->RegisterMessageReceiver(impl::bind_in(receiverId), *(void**)(&messageReceivedCallback)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>::UnregisterMessageReceiver(winrt::guid const& receiverId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment)->UnregisterMessageReceiver(impl::bind_in(receiverId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment2<D>::PostMessageToReceiverAsync(winrt::guid const& receiverId, param::async_iterable<winrt::Windows::Foundation::IInspectable> const& message) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2)->PostMessageToReceiverAsync(impl::bind_in(receiverId), *(void**)(&message), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment2<D>::PostMessageToReceiverAsync(winrt::guid const& receiverId, param::async_iterable<winrt::Windows::Foundation::IInspectable> const& message, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2)->PostMessageToReceiverWithTelemetryAsync(impl::bind_in(receiverId), *(void**)(&message), *(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment3<D>::GetUserInfo() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3)->GetUserInfo(&result));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment3<D>::ShareFileAsync(param::hstring const& filePath, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3)->ShareFileAsync(*(void**)(&filePath), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment3<D>::ShareFileAsync(param::hstring const& filePath, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions const& options, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3)->ShareFileWithTelemetryAsync(*(void**)(&filePath), *(void**)(&options), *(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment4<D>::ChangePriority(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const& Priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4)->ChangePriority(static_cast<int32_t>(Priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult<D>::Environment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult)->get_Environment(&value));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult2<D>::ChangeCreationPriority(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2)->ChangeCreationPriority(static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFactory<D>::CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory)->CreateAsync(*(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFactory<D>::CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory)->CreateWithTelemetryAsync(*(void**)(&options), *(void**)(&telemetryParameters), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFactory<D>::GetById(param::hstring const& environmentId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory)->GetById(*(void**)(&environmentId), &result));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFactory<D>::FindByOwnerId(param::hstring const& environmentOwnerId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory)->FindByOwnerId(*(void**)(&environmentOwnerId), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile<D>::Id() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile<D>::HostPath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile)->get_HostPath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile2<D>::GuestPath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2)->get_GuestPath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile2<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentHostStatics<D>::IsReady() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics)->get_IsReady(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentHostStatics<D>::HostErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics)->get_HostErrors(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentLaunchFileResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentLaunchFileResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentLaunchFileResult<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult)->get_File(&value));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::EnvironmentOwnerId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_EnvironmentOwnerId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::EnvironmentOwnerId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_EnvironmentOwnerId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AllowedClipboardFormats() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_AllowedClipboardFormats(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AllowedClipboardFormats(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_AllowedClipboardFormats(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::ClipboardCopyPasteDirections() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_ClipboardCopyPasteDirections(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::ClipboardCopyPasteDirections(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_ClipboardCopyPasteDirections(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AvailablePrinters() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_AvailablePrinters(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AvailablePrinters(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_AvailablePrinters(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::SharedHostFolderPath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_SharedHostFolderPath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::SharedFolderNameInEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_SharedFolderNameInEnvironment(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::ShareHostFolderForUntrustedItems(param::hstring const& SharedHostFolderPath, param::hstring const& ShareFolderNameInEnvironment) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->ShareHostFolderForUntrustedItems(*(void**)(&SharedHostFolderPath), *(void**)(&ShareFolderNameInEnvironment)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::PersistUserProfile() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_PersistUserProfile(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::PersistUserProfile(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_PersistUserProfile(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AllowGraphicsHardwareAcceleration() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_AllowGraphicsHardwareAcceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AllowGraphicsHardwareAcceleration(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_AllowGraphicsHardwareAcceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AllowCameraAndMicrophoneAccess() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->get_AllowCameraAndMicrophoneAccess(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>::AllowCameraAndMicrophoneAccess(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions)->put_AllowCameraAndMicrophoneAccess(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions2<D>::WindowAnnotationOverride() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2)->get_WindowAnnotationOverride(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions2<D>::WindowAnnotationOverride(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2)->put_WindowAnnotationOverride(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>::AllowedClipboardFormatsToEnvironment() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3)->get_AllowedClipboardFormatsToEnvironment(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>::AllowedClipboardFormatsToEnvironment(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3)->put_AllowedClipboardFormatsToEnvironment(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>::AllowedClipboardFormatsToHost() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3)->get_AllowedClipboardFormatsToHost(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>::AllowedClipboardFormatsToHost(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3)->put_AllowedClipboardFormatsToHost(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>::CreationPriority() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3)->get_CreationPriority(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>::CreationPriority(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3)->put_CreationPriority(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationData<D>::ShareableFolders() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData)->get_ShareableFolders(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationData<D>::ProcessesRunnableAsSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData)->get_ProcessesRunnableAsSystem(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationData<D>::ProcessesRunnableAsUser() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData)->get_ProcessesRunnableAsUser(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationData<D>::ActivationFileExtensions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData)->get_ActivationFileExtensions(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationStatics<D>::Register(param::hstring const& ownerName, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData const& ownerRegistrationData) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics)->Register(*(void**)(&ownerName), *(void**)(&ownerRegistrationData), &result));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationStatics<D>::Unregister(param::hstring const& ownerName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics)->Unregister(*(void**)(&ownerName)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentPostMessageResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentPostMessageResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcessState) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess<D>::State() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcessState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess<D>::ExitCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess)->get_ExitCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess<D>::WaitForExit() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess)->WaitForExit());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess<D>::WaitForExitWithTimeout(uint32_t timeoutMilliseconds) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess)->WaitForExitWithTimeout(timeoutMilliseconds));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess<D>::WaitForExitAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess)->WaitForExitAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileRequestOptions<D>::AllowWrite() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions)->get_AllowWrite(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileRequestOptions<D>::AllowWrite(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions)->put_AllowWrite(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileResult<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult)->get_File(&value));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderRequestOptions<D>::AllowWrite() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions)->get_AllowWrite(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderRequestOptions<D>::AllowWrite(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions)->put_AllowWrite(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessStatus) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentStartProcessResult<D>::Status() const
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentStartProcessResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentStartProcessResult<D>::Process() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult)->get_Process(&value));
        return winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentTelemetryParameters<D>::CorrelationId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters)->get_CorrelationId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentTelemetryParameters<D>::CorrelationId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters)->put_CorrelationId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo<D>::EnvironmentUserSid() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo)->get_EnvironmentUserSid(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo<D>::EnvironmentUserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo)->get_EnvironmentUserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo<D>::TryWaitForSignInAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo)->TryWaitForSignInAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<bool, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentSignInProgress>) consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo2<D>::TryWaitForSignInWithProgressAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2)->TryWaitForSignInWithProgressAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<bool, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentSignInProgress>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics<D>::PostMessageToReceiver(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics)->PostMessageToReceiver(impl::bind_in(receiverId), *(void**)(&message)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics<D>::GetFileId(param::hstring const& filePath) const
    {
        winrt::guid result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics)->GetFileId(*(void**)(&filePath), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics2<D>::RegisterHostMessageReceiver(winrt::guid const& receiverId, winrt::Windows::Security::Isolation::HostMessageReceivedCallback const& hostMessageReceivedCallback) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2)->RegisterHostMessageReceiver(impl::bind_in(receiverId), *(void**)(&hostMessageReceivedCallback)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics2<D>::UnregisterHostMessageReceiver(winrt::guid const& receiverId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2)->UnregisterHostMessageReceiver(impl::bind_in(receiverId)));
    }
    template <typename H> struct delegate<winrt::Windows::Security::Isolation::HostMessageReceivedCallback, H> final : implements_delegate<winrt::Windows::Security::Isolation::HostMessageReceivedCallback, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Security::Isolation::HostMessageReceivedCallback, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(winrt::guid receiverId, void* message) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::IInspectable> const*>(&message));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Security::Isolation::MessageReceivedCallback, H> final : implements_delegate<winrt::Windows::Security::Isolation::MessageReceivedCallback, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Security::Isolation::MessageReceivedCallback, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(winrt::guid receiverId, void* message) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::IInspectable> const*>(&message));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartProcessSilentlyAsync(void* hostExePath, void* arguments, int32_t activator, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>>(this->shim().StartProcessSilentlyAsync(*reinterpret_cast<hstring const*>(&hostExePath), *reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator const*>(&activator)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartProcessSilentlyWithTelemetryAsync(void* hostExePath, void* arguments, int32_t activator, void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>>(this->shim().StartProcessSilentlyAsync(*reinterpret_cast<hstring const*>(&hostExePath), *reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator const*>(&activator), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShareFolderAsync(void* hostFolder, void* requestOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>>(this->shim().ShareFolderAsync(*reinterpret_cast<hstring const*>(&hostFolder), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions const*>(&requestOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShareFolderWithTelemetryAsync(void* hostFolder, void* requestOptions, void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>>(this->shim().ShareFolderAsync(*reinterpret_cast<hstring const*>(&hostFolder), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions const*>(&requestOptions), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFileWithUIAsync(void* appExePath, void* argumentsTemplate, void* filePath, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>>(this->shim().LaunchFileWithUIAsync(*reinterpret_cast<hstring const*>(&appExePath), *reinterpret_cast<hstring const*>(&argumentsTemplate), *reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFileWithUIAndTelemetryAsync(void* appExePath, void* argumentsTemplate, void* filePath, void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>>(this->shim().LaunchFileWithUIAsync(*reinterpret_cast<hstring const*>(&appExePath), *reinterpret_cast<hstring const*>(&argumentsTemplate), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TerminateAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().TerminateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TerminateWithTelemetryAsync(void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().TerminateAsync(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterMessageReceiver(winrt::guid receiverId, void* messageReceivedCallback) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterMessageReceiver(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Security::Isolation::MessageReceivedCallback const*>(&messageReceivedCallback));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterMessageReceiver(winrt::guid receiverId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterMessageReceiver(*reinterpret_cast<winrt::guid const*>(&receiverId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2>
    {
        int32_t __stdcall PostMessageToReceiverAsync(winrt::guid receiverId, void* message, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>>(this->shim().PostMessageToReceiverAsync(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::IInspectable> const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PostMessageToReceiverWithTelemetryAsync(winrt::guid receiverId, void* message, void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>>(this->shim().PostMessageToReceiverAsync(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::IInspectable> const*>(&message), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3>
    {
        int32_t __stdcall GetUserInfo(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo>(this->shim().GetUserInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShareFileAsync(void* filePath, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>>(this->shim().ShareFileAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShareFileWithTelemetryAsync(void* filePath, void* options, void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>>(this->shim().ShareFileAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions const*>(&options), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4>
    {
        int32_t __stdcall ChangePriority(int32_t Priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangePriority(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const*>(&Priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Environment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>(this->shim().Environment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2>
    {
        int32_t __stdcall ChangeCreationPriority(int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangeCreationPriority(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory>
    {
        int32_t __stdcall CreateAsync(void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>>(this->shim().CreateAsync(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTelemetryAsync(void* options, void* telemetryParameters, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>>(this->shim().CreateAsync(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const*>(&options), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const*>(&telemetryParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetById(void* environmentId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>(this->shim().GetById(*reinterpret_cast<hstring const*>(&environmentId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindByOwnerId(void* environmentOwnerId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>>(this->shim().FindByOwnerId(*reinterpret_cast<hstring const*>(&environmentOwnerId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile>
    {
        int32_t __stdcall get_Id(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HostPath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HostPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2>
    {
        int32_t __stdcall get_GuestPath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GuestPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics>
    {
        int32_t __stdcall get_IsReady(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReady());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HostErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError>>(this->shim().HostErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions>
    {
        int32_t __stdcall get_EnvironmentOwnerId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnvironmentOwnerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnvironmentOwnerId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnvironmentOwnerId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedClipboardFormats(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats>(this->shim().AllowedClipboardFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowedClipboardFormats(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowedClipboardFormats(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClipboardCopyPasteDirections(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections>(this->shim().ClipboardCopyPasteDirections());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClipboardCopyPasteDirections(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClipboardCopyPasteDirections(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AvailablePrinters(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters>(this->shim().AvailablePrinters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AvailablePrinters(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AvailablePrinters(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharedHostFolderPath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SharedHostFolderPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharedFolderNameInEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SharedFolderNameInEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShareHostFolderForUntrustedItems(void* SharedHostFolderPath, void* ShareFolderNameInEnvironment) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShareHostFolderForUntrustedItems(*reinterpret_cast<hstring const*>(&SharedHostFolderPath), *reinterpret_cast<hstring const*>(&ShareFolderNameInEnvironment));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PersistUserProfile(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PersistUserProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PersistUserProfile(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PersistUserProfile(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowGraphicsHardwareAcceleration(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowGraphicsHardwareAcceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowGraphicsHardwareAcceleration(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowGraphicsHardwareAcceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowCameraAndMicrophoneAccess(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowCameraAndMicrophoneAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowCameraAndMicrophoneAccess(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowCameraAndMicrophoneAccess(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2>
    {
        int32_t __stdcall get_WindowAnnotationOverride(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WindowAnnotationOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WindowAnnotationOverride(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WindowAnnotationOverride(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3>
    {
        int32_t __stdcall get_AllowedClipboardFormatsToEnvironment(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats>(this->shim().AllowedClipboardFormatsToEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowedClipboardFormatsToEnvironment(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowedClipboardFormatsToEnvironment(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedClipboardFormatsToHost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats>(this->shim().AllowedClipboardFormatsToHost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowedClipboardFormatsToHost(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowedClipboardFormatsToHost(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CreationPriority(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority>(this->shim().CreationPriority());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CreationPriority(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CreationPriority(*reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData>
    {
        int32_t __stdcall get_ShareableFolders(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ShareableFolders());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProcessesRunnableAsSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ProcessesRunnableAsSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProcessesRunnableAsUser(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ProcessesRunnableAsUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActivationFileExtensions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ActivationFileExtensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics>
    {
        int32_t __stdcall Register(void* ownerName, void* ownerRegistrationData, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult>(this->shim().Register(*reinterpret_cast<hstring const*>(&ownerName), *reinterpret_cast<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData const*>(&ownerRegistrationData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Unregister(void* ownerName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Unregister(*reinterpret_cast<hstring const*>(&ownerName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcessState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExitCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForExit() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WaitForExit();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForExitWithTimeout(uint32_t timeoutMilliseconds) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WaitForExitWithTimeout(timeoutMilliseconds);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForExitAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WaitForExitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions>
    {
        int32_t __stdcall get_AllowWrite(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWrite());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWrite(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWrite(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions>
    {
        int32_t __stdcall get_AllowWrite(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWrite());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWrite(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWrite(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Process(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess>(this->shim().Process());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters>
    {
        int32_t __stdcall get_CorrelationId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CorrelationId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CorrelationId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo>
    {
        int32_t __stdcall get_EnvironmentUserSid(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnvironmentUserSid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnvironmentUserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnvironmentUserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryWaitForSignInAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryWaitForSignInAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2>
    {
        int32_t __stdcall TryWaitForSignInWithProgressAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<bool, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentSignInProgress>>(this->shim().TryWaitForSignInWithProgressAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics>
    {
        int32_t __stdcall PostMessageToReceiver(winrt::guid receiverId, void* message) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PostMessageToReceiver(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::IInspectable> const*>(&message));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFileId(void* filePath, winrt::guid* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::guid>(this->shim().GetFileId(*reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2> : produce_base<D, winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2>
    {
        int32_t __stdcall RegisterHostMessageReceiver(winrt::guid receiverId, void* hostMessageReceivedCallback) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterHostMessageReceiver(*reinterpret_cast<winrt::guid const*>(&receiverId), *reinterpret_cast<winrt::Windows::Security::Isolation::HostMessageReceivedCallback const*>(&hostMessageReceivedCallback));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterHostMessageReceiver(winrt::guid receiverId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterHostMessageReceiver(*reinterpret_cast<winrt::guid const*>(&receiverId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::Isolation
{
    constexpr auto operator|(IsolatedWindowsEnvironmentAllowedClipboardFormats const left, IsolatedWindowsEnvironmentAllowedClipboardFormats const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAllowedClipboardFormats>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(IsolatedWindowsEnvironmentAllowedClipboardFormats& left, IsolatedWindowsEnvironmentAllowedClipboardFormats const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(IsolatedWindowsEnvironmentAllowedClipboardFormats const left, IsolatedWindowsEnvironmentAllowedClipboardFormats const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAllowedClipboardFormats>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(IsolatedWindowsEnvironmentAllowedClipboardFormats& left, IsolatedWindowsEnvironmentAllowedClipboardFormats const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(IsolatedWindowsEnvironmentAllowedClipboardFormats const value) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAllowedClipboardFormats>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(IsolatedWindowsEnvironmentAllowedClipboardFormats const left, IsolatedWindowsEnvironmentAllowedClipboardFormats const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAllowedClipboardFormats>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(IsolatedWindowsEnvironmentAllowedClipboardFormats& left, IsolatedWindowsEnvironmentAllowedClipboardFormats const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(IsolatedWindowsEnvironmentAvailablePrinters const left, IsolatedWindowsEnvironmentAvailablePrinters const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAvailablePrinters>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(IsolatedWindowsEnvironmentAvailablePrinters& left, IsolatedWindowsEnvironmentAvailablePrinters const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(IsolatedWindowsEnvironmentAvailablePrinters const left, IsolatedWindowsEnvironmentAvailablePrinters const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAvailablePrinters>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(IsolatedWindowsEnvironmentAvailablePrinters& left, IsolatedWindowsEnvironmentAvailablePrinters const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(IsolatedWindowsEnvironmentAvailablePrinters const value) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAvailablePrinters>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(IsolatedWindowsEnvironmentAvailablePrinters const left, IsolatedWindowsEnvironmentAvailablePrinters const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentAvailablePrinters>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(IsolatedWindowsEnvironmentAvailablePrinters& left, IsolatedWindowsEnvironmentAvailablePrinters const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(IsolatedWindowsEnvironmentClipboardCopyPasteDirections const left, IsolatedWindowsEnvironmentClipboardCopyPasteDirections const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentClipboardCopyPasteDirections>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(IsolatedWindowsEnvironmentClipboardCopyPasteDirections& left, IsolatedWindowsEnvironmentClipboardCopyPasteDirections const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(IsolatedWindowsEnvironmentClipboardCopyPasteDirections const left, IsolatedWindowsEnvironmentClipboardCopyPasteDirections const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentClipboardCopyPasteDirections>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(IsolatedWindowsEnvironmentClipboardCopyPasteDirections& left, IsolatedWindowsEnvironmentClipboardCopyPasteDirections const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(IsolatedWindowsEnvironmentClipboardCopyPasteDirections const value) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentClipboardCopyPasteDirections>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(IsolatedWindowsEnvironmentClipboardCopyPasteDirections const left, IsolatedWindowsEnvironmentClipboardCopyPasteDirections const right) noexcept
    {
        return static_cast<IsolatedWindowsEnvironmentClipboardCopyPasteDirections>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(IsolatedWindowsEnvironmentClipboardCopyPasteDirections& left, IsolatedWindowsEnvironmentClipboardCopyPasteDirections const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto IsolatedWindowsEnvironment::CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options)
    {
        return impl::call_factory<IsolatedWindowsEnvironment, IIsolatedWindowsEnvironmentFactory>([&](IIsolatedWindowsEnvironmentFactory const& f) { return f.CreateAsync(options); });
    }
    inline auto IsolatedWindowsEnvironment::CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters)
    {
        return impl::call_factory<IsolatedWindowsEnvironment, IIsolatedWindowsEnvironmentFactory>([&](IIsolatedWindowsEnvironmentFactory const& f) { return f.CreateAsync(options, telemetryParameters); });
    }
    inline auto IsolatedWindowsEnvironment::GetById(param::hstring const& environmentId)
    {
        return impl::call_factory<IsolatedWindowsEnvironment, IIsolatedWindowsEnvironmentFactory>([&](IIsolatedWindowsEnvironmentFactory const& f) { return f.GetById(environmentId); });
    }
    inline auto IsolatedWindowsEnvironment::FindByOwnerId(param::hstring const& environmentOwnerId)
    {
        return impl::call_factory<IsolatedWindowsEnvironment, IIsolatedWindowsEnvironmentFactory>([&](IIsolatedWindowsEnvironmentFactory const& f) { return f.FindByOwnerId(environmentOwnerId); });
    }
    inline auto IsolatedWindowsEnvironmentHost::IsReady()
    {
        return impl::call_factory_cast<bool(*)(IIsolatedWindowsEnvironmentHostStatics const&), IsolatedWindowsEnvironmentHost, IIsolatedWindowsEnvironmentHostStatics>([](IIsolatedWindowsEnvironmentHostStatics const& f) { return f.IsReady(); });
    }
    inline auto IsolatedWindowsEnvironmentHost::HostErrors()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError>(*)(IIsolatedWindowsEnvironmentHostStatics const&), IsolatedWindowsEnvironmentHost, IIsolatedWindowsEnvironmentHostStatics>([](IIsolatedWindowsEnvironmentHostStatics const& f) { return f.HostErrors(); });
    }
    inline IsolatedWindowsEnvironmentOptions::IsolatedWindowsEnvironmentOptions() :
        IsolatedWindowsEnvironmentOptions(impl::call_factory_cast<IsolatedWindowsEnvironmentOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), IsolatedWindowsEnvironmentOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<IsolatedWindowsEnvironmentOptions>(); }))
    {
    }
    inline auto IsolatedWindowsEnvironmentOwnerRegistration::Register(param::hstring const& ownerName, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData const& ownerRegistrationData)
    {
        return impl::call_factory<IsolatedWindowsEnvironmentOwnerRegistration, IIsolatedWindowsEnvironmentOwnerRegistrationStatics>([&](IIsolatedWindowsEnvironmentOwnerRegistrationStatics const& f) { return f.Register(ownerName, ownerRegistrationData); });
    }
    inline auto IsolatedWindowsEnvironmentOwnerRegistration::Unregister(param::hstring const& ownerName)
    {
        impl::call_factory<IsolatedWindowsEnvironmentOwnerRegistration, IIsolatedWindowsEnvironmentOwnerRegistrationStatics>([&](IIsolatedWindowsEnvironmentOwnerRegistrationStatics const& f) { return f.Unregister(ownerName); });
    }
    inline IsolatedWindowsEnvironmentOwnerRegistrationData::IsolatedWindowsEnvironmentOwnerRegistrationData() :
        IsolatedWindowsEnvironmentOwnerRegistrationData(impl::call_factory_cast<IsolatedWindowsEnvironmentOwnerRegistrationData(*)(winrt::Windows::Foundation::IActivationFactory const&), IsolatedWindowsEnvironmentOwnerRegistrationData>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<IsolatedWindowsEnvironmentOwnerRegistrationData>(); }))
    {
    }
    inline IsolatedWindowsEnvironmentShareFileRequestOptions::IsolatedWindowsEnvironmentShareFileRequestOptions() :
        IsolatedWindowsEnvironmentShareFileRequestOptions(impl::call_factory_cast<IsolatedWindowsEnvironmentShareFileRequestOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), IsolatedWindowsEnvironmentShareFileRequestOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<IsolatedWindowsEnvironmentShareFileRequestOptions>(); }))
    {
    }
    inline IsolatedWindowsEnvironmentShareFolderRequestOptions::IsolatedWindowsEnvironmentShareFolderRequestOptions() :
        IsolatedWindowsEnvironmentShareFolderRequestOptions(impl::call_factory_cast<IsolatedWindowsEnvironmentShareFolderRequestOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), IsolatedWindowsEnvironmentShareFolderRequestOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<IsolatedWindowsEnvironmentShareFolderRequestOptions>(); }))
    {
    }
    inline IsolatedWindowsEnvironmentTelemetryParameters::IsolatedWindowsEnvironmentTelemetryParameters() :
        IsolatedWindowsEnvironmentTelemetryParameters(impl::call_factory_cast<IsolatedWindowsEnvironmentTelemetryParameters(*)(winrt::Windows::Foundation::IActivationFactory const&), IsolatedWindowsEnvironmentTelemetryParameters>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<IsolatedWindowsEnvironmentTelemetryParameters>(); }))
    {
    }
    inline auto IsolatedWindowsHostMessenger::PostMessageToReceiver(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message)
    {
        impl::call_factory<IsolatedWindowsHostMessenger, IIsolatedWindowsHostMessengerStatics>([&](IIsolatedWindowsHostMessengerStatics const& f) { return f.PostMessageToReceiver(receiverId, message); });
    }
    inline auto IsolatedWindowsHostMessenger::GetFileId(param::hstring const& filePath)
    {
        return impl::call_factory<IsolatedWindowsHostMessenger, IIsolatedWindowsHostMessengerStatics>([&](IIsolatedWindowsHostMessengerStatics const& f) { return f.GetFileId(filePath); });
    }
    inline auto IsolatedWindowsHostMessenger::RegisterHostMessageReceiver(winrt::guid const& receiverId, winrt::Windows::Security::Isolation::HostMessageReceivedCallback const& hostMessageReceivedCallback)
    {
        impl::call_factory<IsolatedWindowsHostMessenger, IIsolatedWindowsHostMessengerStatics2>([&](IIsolatedWindowsHostMessengerStatics2 const& f) { return f.RegisterHostMessageReceiver(receiverId, hostMessageReceivedCallback); });
    }
    inline auto IsolatedWindowsHostMessenger::UnregisterHostMessageReceiver(winrt::guid const& receiverId)
    {
        impl::call_factory<IsolatedWindowsHostMessenger, IIsolatedWindowsHostMessengerStatics2>([&](IIsolatedWindowsHostMessengerStatics2 const& f) { return f.UnregisterHostMessageReceiver(receiverId); });
    }
    template <typename L> HostMessageReceivedCallback::HostMessageReceivedCallback(L handler) :
        HostMessageReceivedCallback(impl::make_delegate<HostMessageReceivedCallback>(std::forward<L>(handler)))
    {
    }
    template <typename F> HostMessageReceivedCallback::HostMessageReceivedCallback(F* handler) :
        HostMessageReceivedCallback([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> HostMessageReceivedCallback::HostMessageReceivedCallback(O* object, M method) :
        HostMessageReceivedCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> HostMessageReceivedCallback::HostMessageReceivedCallback(com_ptr<O>&& object, M method) :
        HostMessageReceivedCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> HostMessageReceivedCallback::HostMessageReceivedCallback(weak_ref<O>&& object, M method) :
        HostMessageReceivedCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto HostMessageReceivedCallback::operator()(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message) const
    {
        check_hresult((*(impl::abi_t<HostMessageReceivedCallback>**)this)->Invoke(impl::bind_in(receiverId), *(void**)(&message)));
    }
    template <typename L> MessageReceivedCallback::MessageReceivedCallback(L handler) :
        MessageReceivedCallback(impl::make_delegate<MessageReceivedCallback>(std::forward<L>(handler)))
    {
    }
    template <typename F> MessageReceivedCallback::MessageReceivedCallback(F* handler) :
        MessageReceivedCallback([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> MessageReceivedCallback::MessageReceivedCallback(O* object, M method) :
        MessageReceivedCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> MessageReceivedCallback::MessageReceivedCallback(com_ptr<O>&& object, M method) :
        MessageReceivedCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> MessageReceivedCallback::MessageReceivedCallback(weak_ref<O>&& object, M method) :
        MessageReceivedCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto MessageReceivedCallback::operator()(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message) const
    {
        check_hresult((*(impl::abi_t<MessageReceivedCallback>**)this)->Invoke(impl::bind_in(receiverId), *(void**)(&message)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHost> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Isolation::IsolatedWindowsHostMessenger> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
