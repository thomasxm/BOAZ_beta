// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_H
#define WINRT_Windows_System_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.Diagnostics.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.2.h"
#include "winrt/impl/Windows.System.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_System_IAppActivationResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppActivationResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupInfo) consume_Windows_System_IAppActivationResult<D>::AppResourceGroupInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppActivationResult)->get_AppResourceGroupInfo(&value));
        return winrt::Windows::System::AppResourceGroupInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppInfo) consume_Windows_System_IAppDiagnosticInfo<D>::AppInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfo)->get_AppInfo(&value));
        return winrt::Windows::ApplicationModel::AppInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppResourceGroupInfo>) consume_Windows_System_IAppDiagnosticInfo2<D>::GetResourceGroups() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfo2)->GetResourceGroups(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppResourceGroupInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupInfoWatcher) consume_Windows_System_IAppDiagnosticInfo2<D>::CreateResourceGroupWatcher() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfo2)->CreateResourceGroupWatcher(&result));
        return winrt::Windows::System::AppResourceGroupInfoWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppActivationResult>) consume_Windows_System_IAppDiagnosticInfo3<D>::LaunchAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfo3)->LaunchAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppActivationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>) consume_Windows_System_IAppDiagnosticInfoStatics<D>::RequestInfoAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoStatics)->RequestInfoAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppDiagnosticInfoWatcher) consume_Windows_System_IAppDiagnosticInfoStatics2<D>::CreateWatcher() const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoStatics2)->CreateWatcher(&watcher));
        return winrt::Windows::System::AppDiagnosticInfoWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::DiagnosticAccessStatus>) consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoStatics2)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::DiagnosticAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>) consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestInfoForPackageAsync(param::hstring const& packageFamilyName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoStatics2)->RequestInfoForPackageAsync(*(void**)(&packageFamilyName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>) consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestInfoForAppAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoStatics2)->RequestInfoForAppAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>) consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestInfoForAppAsync(param::hstring const& appUserModelId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoStatics2)->RequestInfoForAppUserModelId(*(void**)(&appUserModelId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppDiagnosticInfoWatcherStatus) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Status() const
    {
        winrt::Windows::System::AppDiagnosticInfoWatcherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppDiagnosticInfo) consume_Windows_System_IAppDiagnosticInfoWatcherEventArgs<D>::AppDiagnosticInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppDiagnosticInfoWatcherEventArgs)->get_AppDiagnosticInfo(&value));
        return winrt::Windows::System::AppDiagnosticInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_System_IAppExecutionStateChangeResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppExecutionStateChangeResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryReport<D>::PrivateCommitUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryReport)->get_PrivateCommitUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryReport<D>::PeakPrivateCommitUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryReport)->get_PeakPrivateCommitUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryReport<D>::TotalCommitUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryReport)->get_TotalCommitUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryReport<D>::TotalCommitLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryReport)->get_TotalCommitLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryReport2<D>::ExpectedTotalCommitLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryReport2)->get_ExpectedTotalCommitLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryUsageLimitChangingEventArgs<D>::OldLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs)->get_OldLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppMemoryUsageLimitChangingEventArgs<D>::NewLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs)->get_NewLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::TaskId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupBackgroundTaskReport)->get_TaskId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupBackgroundTaskReport)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::Trigger() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupBackgroundTaskReport)->get_Trigger(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::EntryPoint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupBackgroundTaskReport)->get_EntryPoint(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_System_IAppResourceGroupInfo<D>::InstanceId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo)->get_InstanceId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IAppResourceGroupInfo<D>::IsShared() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo)->get_IsShared(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppResourceGroupBackgroundTaskReport>) consume_Windows_System_IAppResourceGroupInfo<D>::GetBackgroundTaskReports() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo)->GetBackgroundTaskReports(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppResourceGroupBackgroundTaskReport>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupMemoryReport) consume_Windows_System_IAppResourceGroupInfo<D>::GetMemoryReport() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo)->GetMemoryReport(&result));
        return winrt::Windows::System::AppResourceGroupMemoryReport{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo>) consume_Windows_System_IAppResourceGroupInfo<D>::GetProcessDiagnosticInfos() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo)->GetProcessDiagnosticInfos(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupStateReport) consume_Windows_System_IAppResourceGroupInfo<D>::GetStateReport() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo)->GetStateReport(&result));
        return winrt::Windows::System::AppResourceGroupStateReport{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>) consume_Windows_System_IAppResourceGroupInfo2<D>::StartSuspendAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo2)->StartSuspendAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>) consume_Windows_System_IAppResourceGroupInfo2<D>::StartResumeAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo2)->StartResumeAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>) consume_Windows_System_IAppResourceGroupInfo2<D>::StartTerminateAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfo2)->StartTerminateAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->add_ExecutionStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ExecutionStateChanged_revoker>(this, ExecutionStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->remove_ExecutionStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupInfoWatcherStatus) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Status() const
    {
        winrt::Windows::System::AppResourceGroupInfoWatcherStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::AppDiagnosticInfo>) consume_Windows_System_IAppResourceGroupInfoWatcherEventArgs<D>::AppDiagnosticInfos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs)->get_AppDiagnosticInfos(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::AppDiagnosticInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupInfo) consume_Windows_System_IAppResourceGroupInfoWatcherEventArgs<D>::AppResourceGroupInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs)->get_AppResourceGroupInfo(&value));
        return winrt::Windows::System::AppResourceGroupInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::AppDiagnosticInfo>) consume_Windows_System_IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs<D>::AppDiagnosticInfos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs)->get_AppDiagnosticInfos(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::AppDiagnosticInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupInfo) consume_Windows_System_IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs<D>::AppResourceGroupInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs)->get_AppResourceGroupInfo(&value));
        return winrt::Windows::System::AppResourceGroupInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppResourceGroupMemoryReport<D>::CommitUsageLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupMemoryReport)->get_CommitUsageLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppMemoryUsageLevel) consume_Windows_System_IAppResourceGroupMemoryReport<D>::CommitUsageLevel() const
    {
        winrt::Windows::System::AppMemoryUsageLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupMemoryReport)->get_CommitUsageLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppResourceGroupMemoryReport<D>::PrivateCommitUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupMemoryReport)->get_PrivateCommitUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IAppResourceGroupMemoryReport<D>::TotalCommitUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupMemoryReport)->get_TotalCommitUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupExecutionState) consume_Windows_System_IAppResourceGroupStateReport<D>::ExecutionState() const
    {
        winrt::Windows::System::AppResourceGroupExecutionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupStateReport)->get_ExecutionState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppResourceGroupEnergyQuotaState) consume_Windows_System_IAppResourceGroupStateReport<D>::EnergyQuotaState() const
    {
        winrt::Windows::System::AppResourceGroupEnergyQuotaState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppResourceGroupStateReport)->get_EnergyQuotaState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppUriHandlerHost<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerHost)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppUriHandlerHost<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerHost)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IAppUriHandlerHost2<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerHost2)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppUriHandlerHost2<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerHost2)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppUriHandlerHost) consume_Windows_System_IAppUriHandlerHostFactory<D>::CreateInstance(param::hstring const& name) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerHostFactory)->CreateInstance(*(void**)(&name), &value));
        return winrt::Windows::System::AppUriHandlerHost{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppUriHandlerRegistration<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IAppUriHandlerRegistration<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppUriHandlerHost>>) consume_Windows_System_IAppUriHandlerRegistration<D>::GetAppAddedHostsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration)->GetAppAddedHostsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppUriHandlerHost>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_System_IAppUriHandlerRegistration<D>::SetAppAddedHostsAsync(param::async_iterable<winrt::Windows::System::AppUriHandlerHost> const& hosts) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration)->SetAppAddedHostsAsync(*(void**)(&hosts), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppUriHandlerHost>) consume_Windows_System_IAppUriHandlerRegistration2<D>::GetAllHosts() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration2)->GetAllHosts(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppUriHandlerHost>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IAppUriHandlerRegistration2<D>::UpdateHosts(param::iterable<winrt::Windows::System::AppUriHandlerHost> const& hosts) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration2)->UpdateHosts(*(void**)(&hosts)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppUriHandlerRegistration2<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistration2)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IAppUriHandlerRegistrationManager<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManager)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppUriHandlerRegistration) consume_Windows_System_IAppUriHandlerRegistrationManager<D>::TryGetRegistration(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManager)->TryGetRegistration(*(void**)(&name), &result));
        return winrt::Windows::System::AppUriHandlerRegistration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IAppUriHandlerRegistrationManager2<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManager2)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppUriHandlerRegistrationManager) consume_Windows_System_IAppUriHandlerRegistrationManagerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics)->GetDefault(&result));
        return winrt::Windows::System::AppUriHandlerRegistrationManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppUriHandlerRegistrationManager) consume_Windows_System_IAppUriHandlerRegistrationManagerStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::System::AppUriHandlerRegistrationManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppUriHandlerRegistrationManager) consume_Windows_System_IAppUriHandlerRegistrationManagerStatics2<D>::GetForPackage(param::hstring const& packageFamilyName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics2)->GetForPackage(*(void**)(&packageFamilyName), &result));
        return winrt::Windows::System::AppUriHandlerRegistrationManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppUriHandlerRegistrationManager) consume_Windows_System_IAppUriHandlerRegistrationManagerStatics2<D>::GetForPackageForUser(param::hstring const& packageFamilyName, winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics2)->GetForPackageForUser(*(void**)(&packageFamilyName), *(void**)(&user), &result));
        return winrt::Windows::System::AppUriHandlerRegistrationManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDateTimeSettingsStatics<D>::SetSystemDateTime(winrt::Windows::Foundation::DateTime const& utcDateTime) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDateTimeSettingsStatics)->SetSystemDateTime(impl::bind_in(utcDateTime)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueueTimer) consume_Windows_System_IDispatcherQueue<D>::CreateTimer() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->CreateTimer(&result));
        return winrt::Windows::System::DispatcherQueueTimer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IDispatcherQueue<D>::TryEnqueue(winrt::Windows::System::DispatcherQueueHandler const& callback) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->TryEnqueue(*(void**)(&callback), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IDispatcherQueue<D>::TryEnqueue(winrt::Windows::System::DispatcherQueuePriority const& priority, winrt::Windows::System::DispatcherQueueHandler const& callback) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->TryEnqueueWithPriority(static_cast<int32_t>(priority), *(void**)(&callback), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueue, winrt::Windows::System::DispatcherQueueShutdownStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->add_ShutdownStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting_revoker consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueue, winrt::Windows::System::DispatcherQueueShutdownStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ShutdownStarting_revoker>(this, ShutdownStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->remove_ShutdownStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueue, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->add_ShutdownCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted_revoker consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueue, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ShutdownCompleted_revoker>(this, ShutdownCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue)->remove_ShutdownCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IDispatcherQueue2<D>::HasThreadAccess() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueue2)->get_HasThreadAccess(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) consume_Windows_System_IDispatcherQueueController<D>::DispatcherQueue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueController)->get_DispatcherQueue(&value));
        return winrt::Windows::System::DispatcherQueue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_System_IDispatcherQueueController<D>::ShutdownQueueAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueController)->ShutdownQueueAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueueController) consume_Windows_System_IDispatcherQueueControllerStatics<D>::CreateOnDedicatedThread() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueControllerStatics)->CreateOnDedicatedThread(&result));
        return winrt::Windows::System::DispatcherQueueController{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_System_IDispatcherQueueShutdownStartingEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueShutdownStartingEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) consume_Windows_System_IDispatcherQueueStatics<D>::GetForCurrentThread() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueStatics)->GetForCurrentThread(&result));
        return winrt::Windows::System::DispatcherQueue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_System_IDispatcherQueueTimer<D>::Interval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->get_Interval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueueTimer<D>::Interval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->put_Interval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IDispatcherQueueTimer<D>::IsRunning() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->get_IsRunning(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IDispatcherQueueTimer<D>::IsRepeating() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->get_IsRepeating(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueueTimer<D>::IsRepeating(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->put_IsRepeating(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueueTimer<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueueTimer<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IDispatcherQueueTimer<D>::Tick(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueueTimer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->add_Tick(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IDispatcherQueueTimer<D>::Tick_revoker consume_Windows_System_IDispatcherQueueTimer<D>::Tick(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueueTimer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Tick_revoker>(this, Tick(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IDispatcherQueueTimer<D>::Tick(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IDispatcherQueueTimer)->remove_Tick(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::IStorageItem>) consume_Windows_System_IFolderLauncherOptions<D>::ItemsToSelect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IFolderLauncherOptions)->get_ItemsToSelect(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::IStorageItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::FirstName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_FirstName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::LastName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_LastName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::ProviderName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_ProviderName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::AccountName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_AccountName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::GuestHost() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_GuestHost(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::PrincipalName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_PrincipalName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::DomainName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_DomainName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics<D>::SessionInitiationProtocolUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics)->get_SessionInitiationProtocolUri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IKnownUserPropertiesStatics2<D>::AgeEnforcementRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IKnownUserPropertiesStatics2)->get_AgeEnforcementRegion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::LaunchUriStatus) consume_Windows_System_ILaunchUriResult<D>::Status() const
    {
        winrt::Windows::System::LaunchUriStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILaunchUriResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_System_ILaunchUriResult<D>::Result() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILaunchUriResult)->get_Result(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_ILauncherOptions<D>::TreatAsUntrusted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_TreatAsUntrusted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions<D>::TreatAsUntrusted(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->put_TreatAsUntrusted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_ILauncherOptions<D>::DisplayApplicationPicker() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_DisplayApplicationPicker(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions<D>::DisplayApplicationPicker(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->put_DisplayApplicationPicker(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::LauncherUIOptions) consume_Windows_System_ILauncherOptions<D>::UI() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_UI(&value));
        return winrt::Windows::System::LauncherUIOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_ILauncherOptions<D>::PreferredApplicationPackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_PreferredApplicationPackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions<D>::PreferredApplicationPackageFamilyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->put_PreferredApplicationPackageFamilyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_ILauncherOptions<D>::PreferredApplicationDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_PreferredApplicationDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions<D>::PreferredApplicationDisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->put_PreferredApplicationDisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_System_ILauncherOptions<D>::FallbackUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_FallbackUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions<D>::FallbackUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->put_FallbackUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_ILauncherOptions<D>::ContentType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->get_ContentType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions<D>::ContentType(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions)->put_ContentType(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_ILauncherOptions2<D>::TargetApplicationPackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions2)->get_TargetApplicationPackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions2<D>::TargetApplicationPackageFamilyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions2)->put_TargetApplicationPackageFamilyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Search::StorageFileQueryResult) consume_Windows_System_ILauncherOptions2<D>::NeighboringFilesQuery() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions2)->get_NeighboringFilesQuery(&value));
        return winrt::Windows::Storage::Search::StorageFileQueryResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions2<D>::NeighboringFilesQuery(winrt::Windows::Storage::Search::StorageFileQueryResult const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions2)->put_NeighboringFilesQuery(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_ILauncherOptions3<D>::IgnoreAppUriHandlers() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions3)->get_IgnoreAppUriHandlers(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions3<D>::IgnoreAppUriHandlers(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions3)->put_IgnoreAppUriHandlers(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_ILauncherOptions4<D>::LimitPickerToCurrentAppAndAppUriHandlers() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions4)->get_LimitPickerToCurrentAppAndAppUriHandlers(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherOptions4<D>::LimitPickerToCurrentAppAndAppUriHandlers(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherOptions4)->put_LimitPickerToCurrentAppAndAppUriHandlers(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics<D>::LaunchFileAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics)->LaunchFileAsync(*(void**)(&file), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics<D>::LaunchFileAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::System::LauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics)->LaunchFileWithOptionsAsync(*(void**)(&file), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics<D>::LaunchUriAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics)->LaunchUriAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics<D>::LaunchUriAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics)->LaunchUriWithOptionsAsync(*(void**)(&uri), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>) consume_Windows_System_ILauncherStatics2<D>::LaunchUriForResultsAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->LaunchUriForResultsAsync(*(void**)(&uri), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>) consume_Windows_System_ILauncherStatics2<D>::LaunchUriForResultsAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->LaunchUriForResultsWithDataAsync(*(void**)(&uri), *(void**)(&options), *(void**)(&inputData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics2<D>::LaunchUriAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->LaunchUriWithDataAsync(*(void**)(&uri), *(void**)(&options), *(void**)(&inputData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>) consume_Windows_System_ILauncherStatics2<D>::QueryUriSupportAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LaunchQuerySupportType const& launchQuerySupportType) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->QueryUriSupportAsync(*(void**)(&uri), static_cast<int32_t>(launchQuerySupportType), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>) consume_Windows_System_ILauncherStatics2<D>::QueryUriSupportAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LaunchQuerySupportType const& launchQuerySupportType, param::hstring const& packageFamilyName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->QueryUriSupportWithPackageFamilyNameAsync(*(void**)(&uri), static_cast<int32_t>(launchQuerySupportType), *(void**)(&packageFamilyName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>) consume_Windows_System_ILauncherStatics2<D>::QueryFileSupportAsync(winrt::Windows::Storage::StorageFile const& file) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->QueryFileSupportAsync(*(void**)(&file), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>) consume_Windows_System_ILauncherStatics2<D>::QueryFileSupportAsync(winrt::Windows::Storage::StorageFile const& file, param::hstring const& packageFamilyName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->QueryFileSupportWithPackageFamilyNameAsync(*(void**)(&file), *(void**)(&packageFamilyName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>) consume_Windows_System_ILauncherStatics2<D>::FindUriSchemeHandlersAsync(param::hstring const& scheme) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->FindUriSchemeHandlersAsync(*(void**)(&scheme), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>) consume_Windows_System_ILauncherStatics2<D>::FindUriSchemeHandlersAsync(param::hstring const& scheme, winrt::Windows::System::LaunchQuerySupportType const& launchQuerySupportType) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->FindUriSchemeHandlersWithLaunchUriTypeAsync(*(void**)(&scheme), static_cast<int32_t>(launchQuerySupportType), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>) consume_Windows_System_ILauncherStatics2<D>::FindFileHandlersAsync(param::hstring const& extension) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics2)->FindFileHandlersAsync(*(void**)(&extension), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics3<D>::LaunchFolderAsync(winrt::Windows::Storage::IStorageFolder const& folder) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics3)->LaunchFolderAsync(*(void**)(&folder), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics3<D>::LaunchFolderAsync(winrt::Windows::Storage::IStorageFolder const& folder, winrt::Windows::System::FolderLauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics3)->LaunchFolderWithOptionsAsync(*(void**)(&folder), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>) consume_Windows_System_ILauncherStatics4<D>::QueryAppUriSupportAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->QueryAppUriSupportAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>) consume_Windows_System_ILauncherStatics4<D>::QueryAppUriSupportAsync(winrt::Windows::Foundation::Uri const& uri, param::hstring const& packageFamilyName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->QueryAppUriSupportWithPackageFamilyNameAsync(*(void**)(&uri), *(void**)(&packageFamilyName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>) consume_Windows_System_ILauncherStatics4<D>::FindAppUriHandlersAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->FindAppUriHandlersAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>) consume_Windows_System_ILauncherStatics4<D>::LaunchUriForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->LaunchUriForUserAsync(*(void**)(&user), *(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>) consume_Windows_System_ILauncherStatics4<D>::LaunchUriForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->LaunchUriWithOptionsForUserAsync(*(void**)(&user), *(void**)(&uri), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>) consume_Windows_System_ILauncherStatics4<D>::LaunchUriForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->LaunchUriWithDataForUserAsync(*(void**)(&user), *(void**)(&uri), *(void**)(&options), *(void**)(&inputData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>) consume_Windows_System_ILauncherStatics4<D>::LaunchUriForResultsForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->LaunchUriForResultsForUserAsync(*(void**)(&user), *(void**)(&uri), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>) consume_Windows_System_ILauncherStatics4<D>::LaunchUriForResultsForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics4)->LaunchUriForResultsWithDataForUserAsync(*(void**)(&user), *(void**)(&uri), *(void**)(&options), *(void**)(&inputData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathAsync(param::hstring const& path) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics5)->LaunchFolderPathAsync(*(void**)(&path), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathAsync(param::hstring const& path, winrt::Windows::System::FolderLauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics5)->LaunchFolderPathWithOptionsAsync(*(void**)(&path), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics5)->LaunchFolderPathForUserAsync(*(void**)(&user), *(void**)(&path), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path, winrt::Windows::System::FolderLauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherStatics5)->LaunchFolderPathWithOptionsForUserAsync(*(void**)(&user), *(void**)(&path), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_System_ILauncherUIOptions<D>::InvocationPoint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherUIOptions)->get_InvocationPoint(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherUIOptions<D>::InvocationPoint(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherUIOptions)->put_InvocationPoint(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>) consume_Windows_System_ILauncherUIOptions<D>::SelectionRect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherUIOptions)->get_SelectionRect(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherUIOptions<D>::SelectionRect(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherUIOptions)->put_SelectionRect(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Popups::Placement) consume_Windows_System_ILauncherUIOptions<D>::PreferredPlacement() const
    {
        winrt::Windows::UI::Popups::Placement value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherUIOptions)->get_PreferredPlacement(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherUIOptions<D>::PreferredPlacement(winrt::Windows::UI::Popups::Placement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherUIOptions)->put_PreferredPlacement(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ViewSizePreference) consume_Windows_System_ILauncherViewOptions<D>::DesiredRemainingView() const
    {
        winrt::Windows::UI::ViewManagement::ViewSizePreference value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherViewOptions)->get_DesiredRemainingView(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ILauncherViewOptions<D>::DesiredRemainingView(winrt::Windows::UI::ViewManagement::ViewSizePreference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ILauncherViewOptions)->put_DesiredRemainingView(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->get_AppMemoryUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->get_AppMemoryUsageLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppMemoryUsageLevel) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLevel() const
    {
        winrt::Windows::System::AppMemoryUsageLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->get_AppMemoryUsageLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->add_AppMemoryUsageIncreased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased_revoker consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AppMemoryUsageIncreased_revoker>(this, AppMemoryUsageIncreased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->remove_AppMemoryUsageIncreased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->add_AppMemoryUsageDecreased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased_revoker consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AppMemoryUsageDecreased_revoker>(this, AppMemoryUsageDecreased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->remove_AppMemoryUsageDecreased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging(winrt::Windows::Foundation::EventHandler<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->add_AppMemoryUsageLimitChanging(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging_revoker consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AppMemoryUsageLimitChanging_revoker>(this, AppMemoryUsageLimitChanging(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics)->remove_AppMemoryUsageLimitChanging(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::AppMemoryReport) consume_Windows_System_IMemoryManagerStatics2<D>::GetAppMemoryReport() const
    {
        void* memoryReport{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics2)->GetAppMemoryReport(&memoryReport));
        return winrt::Windows::System::AppMemoryReport{ memoryReport, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::ProcessMemoryReport) consume_Windows_System_IMemoryManagerStatics2<D>::GetProcessMemoryReport() const
    {
        void* memoryReport{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics2)->GetProcessMemoryReport(&memoryReport));
        return winrt::Windows::System::ProcessMemoryReport{ memoryReport, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IMemoryManagerStatics3<D>::TrySetAppMemoryUsageLimit(uint64_t value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics3)->TrySetAppMemoryUsageLimit(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IMemoryManagerStatics4<D>::ExpectedAppMemoryUsageLimit() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IMemoryManagerStatics4)->get_ExpectedAppMemoryUsageLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_System_IProcessLauncherOptions<D>::StandardInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->get_StandardInput(&value));
        return winrt::Windows::Storage::Streams::IInputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IProcessLauncherOptions<D>::StandardInput(winrt::Windows::Storage::Streams::IInputStream const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->put_StandardInput(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_System_IProcessLauncherOptions<D>::StandardOutput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->get_StandardOutput(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IProcessLauncherOptions<D>::StandardOutput(winrt::Windows::Storage::Streams::IOutputStream const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->put_StandardOutput(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_System_IProcessLauncherOptions<D>::StandardError() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->get_StandardError(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IProcessLauncherOptions<D>::StandardError(winrt::Windows::Storage::Streams::IOutputStream const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->put_StandardError(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IProcessLauncherOptions<D>::WorkingDirectory() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->get_WorkingDirectory(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IProcessLauncherOptions<D>::WorkingDirectory(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherOptions)->put_WorkingDirectory(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_IProcessLauncherResult<D>::ExitCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherResult)->get_ExitCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::ProcessLauncherResult>) consume_Windows_System_IProcessLauncherStatics<D>::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args) const
    {
        void* asyncOperationResult{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherStatics)->RunToCompletionAsync(*(void**)(&fileName), *(void**)(&args), &asyncOperationResult));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::ProcessLauncherResult>{ asyncOperationResult, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::ProcessLauncherResult>) consume_Windows_System_IProcessLauncherStatics<D>::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args, winrt::Windows::System::ProcessLauncherOptions const& options) const
    {
        void* asyncOperationResult{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessLauncherStatics)->RunToCompletionAsyncWithOptions(*(void**)(&fileName), *(void**)(&args), *(void**)(&options), &asyncOperationResult));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::ProcessLauncherResult>{ asyncOperationResult, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IProcessMemoryReport<D>::PrivateWorkingSetUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessMemoryReport)->get_PrivateWorkingSetUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_IProcessMemoryReport<D>::TotalWorkingSetUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProcessMemoryReport)->get_TotalWorkingSetUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IProtocolForResultsOperation<D>::ReportCompleted(winrt::Windows::Foundation::Collections::ValueSet const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IProtocolForResultsOperation)->ReportCompleted(*(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_System_IRemoteLauncherOptions<D>::FallbackUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IRemoteLauncherOptions)->get_FallbackUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IRemoteLauncherOptions<D>::FallbackUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IRemoteLauncherOptions)->put_FallbackUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_System_IRemoteLauncherOptions<D>::PreferredAppIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IRemoteLauncherOptions)->get_PreferredAppIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>) consume_Windows_System_IRemoteLauncherStatics<D>::LaunchUriAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IRemoteLauncherStatics)->LaunchUriAsync(*(void**)(&remoteSystemConnectionRequest), *(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>) consume_Windows_System_IRemoteLauncherStatics<D>::LaunchUriAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::RemoteLauncherOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IRemoteLauncherStatics)->LaunchUriWithOptionsAsync(*(void**)(&remoteSystemConnectionRequest), *(void**)(&uri), *(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>) consume_Windows_System_IRemoteLauncherStatics<D>::LaunchUriAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::RemoteLauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IRemoteLauncherStatics)->LaunchUriWithDataAsync(*(void**)(&remoteSystemConnectionRequest), *(void**)(&uri), *(void**)(&options), *(void**)(&inputData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IShutdownManagerStatics<D>::BeginShutdown(winrt::Windows::System::ShutdownKind const& shutdownKind, winrt::Windows::Foundation::TimeSpan const& timeout) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IShutdownManagerStatics)->BeginShutdown(static_cast<int32_t>(shutdownKind), impl::bind_in(timeout)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IShutdownManagerStatics<D>::CancelShutdown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IShutdownManagerStatics)->CancelShutdown());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IShutdownManagerStatics2<D>::IsPowerStateSupported(winrt::Windows::System::PowerState const& powerState) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IShutdownManagerStatics2)->IsPowerStateSupported(static_cast<int32_t>(powerState), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IShutdownManagerStatics2<D>::EnterPowerState(winrt::Windows::System::PowerState const& powerState) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IShutdownManagerStatics2)->EnterPowerState(static_cast<int32_t>(powerState)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IShutdownManagerStatics2<D>::EnterPowerState(winrt::Windows::System::PowerState const& powerState, winrt::Windows::Foundation::TimeSpan const& wakeUpAfter) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IShutdownManagerStatics2)->EnterPowerStateWithTimeSpan(static_cast<int32_t>(powerState), impl::bind_in(wakeUpAfter)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_ITimeZoneSettingsStatics<D>::CurrentTimeZoneDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ITimeZoneSettingsStatics)->get_CurrentTimeZoneDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_System_ITimeZoneSettingsStatics<D>::SupportedTimeZoneDisplayNames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ITimeZoneSettingsStatics)->get_SupportedTimeZoneDisplayNames(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_ITimeZoneSettingsStatics<D>::CanChangeTimeZone() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ITimeZoneSettingsStatics)->get_CanChangeTimeZone(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_ITimeZoneSettingsStatics<D>::ChangeTimeZoneByDisplayName(param::hstring const& timeZoneDisplayName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ITimeZoneSettingsStatics)->ChangeTimeZoneByDisplayName(*(void**)(&timeZoneDisplayName)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AutoUpdateTimeZoneStatus>) consume_Windows_System_ITimeZoneSettingsStatics2<D>::AutoUpdateTimeZoneAsync(winrt::Windows::Foundation::TimeSpan const& timeout) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::ITimeZoneSettingsStatics2)->AutoUpdateTimeZoneAsync(impl::bind_in(timeout), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AutoUpdateTimeZoneStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IUser<D>::NonRoamableId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser)->get_NonRoamableId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserAuthenticationStatus) consume_Windows_System_IUser<D>::AuthenticationStatus() const
    {
        winrt::Windows::System::UserAuthenticationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser)->get_AuthenticationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserType) consume_Windows_System_IUser<D>::Type() const
    {
        winrt::Windows::System::UserType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable>) consume_Windows_System_IUser<D>::GetPropertyAsync(param::hstring const& value) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser)->GetPropertyAsync(*(void**)(&value), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IPropertySet>) consume_Windows_System_IUser<D>::GetPropertiesAsync(param::async_vector_view<hstring> const& values) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser)->GetPropertiesAsync(*(void**)(&values), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IPropertySet>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>) consume_Windows_System_IUser<D>::GetPictureAsync(winrt::Windows::System::UserPictureSize const& desiredSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser)->GetPictureAsync(static_cast<int32_t>(desiredSize), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserAgeConsentResult>) consume_Windows_System_IUser2<D>::CheckUserAgeConsentGroupAsync(winrt::Windows::System::UserAgeConsentGroup const& consentGroup) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUser2)->CheckUserAgeConsentGroupAsync(static_cast<int32_t>(consentGroup), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserAgeConsentResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserAuthenticationStatusChangeDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserAuthenticationStatusChangeDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserAuthenticationStatusChangeDeferral) consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs)->GetDeferral(&result));
        return winrt::Windows::System::UserAuthenticationStatusChangeDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserAuthenticationStatus) consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::NewStatus() const
    {
        winrt::Windows::System::UserAuthenticationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs)->get_NewStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserAuthenticationStatus) consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::CurrentStatus() const
    {
        winrt::Windows::System::UserAuthenticationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs)->get_CurrentStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserChangedEventArgs<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserChangedEventArgs)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::UserWatcherUpdateKind>) consume_Windows_System_IUserChangedEventArgs2<D>::ChangedPropertyKinds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserChangedEventArgs2)->get_ChangedPropertyKinds(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::UserWatcherUpdateKind>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_IUserDeviceAssociationChangedEventArgs<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserDeviceAssociationChangedEventArgs)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserDeviceAssociationChangedEventArgs<D>::NewUser() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserDeviceAssociationChangedEventArgs)->get_NewUser(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserDeviceAssociationChangedEventArgs<D>::OldUser() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserDeviceAssociationChangedEventArgs)->get_OldUser(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserDeviceAssociationStatics<D>::FindUserFromDeviceId(param::hstring const& deviceId) const
    {
        void* user{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserDeviceAssociationStatics)->FindUserFromDeviceId(*(void**)(&deviceId), &user));
        return winrt::Windows::System::User{ user, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserDeviceAssociationStatics)->add_UserDeviceAssociationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged_revoker consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, UserDeviceAssociationChanged_revoker>(this, UserDeviceAssociationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserDeviceAssociationStatics)->remove_UserDeviceAssociationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IUserPicker<D>::AllowGuestAccounts() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserPicker)->get_AllowGuestAccounts(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserPicker<D>::AllowGuestAccounts(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserPicker)->put_AllowGuestAccounts(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserPicker<D>::SuggestedSelectedUser() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserPicker)->get_SuggestedSelectedUser(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserPicker<D>::SuggestedSelectedUser(winrt::Windows::System::User const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserPicker)->put_SuggestedSelectedUser(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::User>) consume_Windows_System_IUserPicker<D>::PickSingleUserAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserPicker)->PickSingleUserAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::User>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_IUserPickerStatics<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserPickerStatics)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserWatcher) consume_Windows_System_IUserStatics<D>::CreateWatcher() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserStatics)->CreateWatcher(&result));
        return winrt::Windows::System::UserWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>) consume_Windows_System_IUserStatics<D>::FindAllAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserStatics)->FindAllAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>) consume_Windows_System_IUserStatics<D>::FindAllAsync(winrt::Windows::System::UserType const& type) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserStatics)->FindAllAsyncByType(static_cast<int32_t>(type), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>) consume_Windows_System_IUserStatics<D>::FindAllAsync(winrt::Windows::System::UserType const& type, winrt::Windows::System::UserAuthenticationStatus const& status) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserStatics)->FindAllAsyncByTypeAndStatus(static_cast<int32_t>(type), static_cast<int32_t>(status), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserStatics<D>::GetFromId(param::hstring const& nonRoamableId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserStatics)->GetFromId(*(void**)(&nonRoamableId), &result));
        return winrt::Windows::System::User{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_IUserStatics2<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserStatics2)->GetDefault(&result));
        return winrt::Windows::System::User{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::UserWatcherStatus) consume_Windows_System_IUserWatcher<D>::Status() const
    {
        winrt::Windows::System::UserWatcherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::Added_revoker consume_Windows_System_IUserWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::Removed_revoker consume_Windows_System_IUserWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::Updated_revoker consume_Windows_System_IUserWatcher<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_AuthenticationStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged_revoker consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AuthenticationStatusChanged_revoker>(this, AuthenticationStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_AuthenticationStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserAuthenticationStatusChangingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_AuthenticationStatusChanging(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging_revoker consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserAuthenticationStatusChangingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AuthenticationStatusChanging_revoker>(this, AuthenticationStatusChanging(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_AuthenticationStatusChanging(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_IUserWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_IUserWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_IUserWatcher<D>::Stopped_revoker consume_Windows_System_IUserWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_IUserWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::IUserWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename H> struct delegate<winrt::Windows::System::DispatcherQueueHandler, H> final : implements_delegate<winrt::Windows::System::DispatcherQueueHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::System::DispatcherQueueHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke() noexcept final try
        {
            (*this)();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppActivationResult> : produce_base<D, winrt::Windows::System::IAppActivationResult>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppResourceGroupInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppResourceGroupInfo>(this->shim().AppResourceGroupInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfo> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfo>
    {
        int32_t __stdcall get_AppInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppInfo>(this->shim().AppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfo2> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfo2>
    {
        int32_t __stdcall GetResourceGroups(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppResourceGroupInfo>>(this->shim().GetResourceGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResourceGroupWatcher(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppResourceGroupInfoWatcher>(this->shim().CreateResourceGroupWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfo3> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfo3>
    {
        int32_t __stdcall LaunchAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppActivationResult>>(this->shim().LaunchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfoStatics> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfoStatics>
    {
        int32_t __stdcall RequestInfoAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfoStatics2> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfoStatics2>
    {
        int32_t __stdcall CreateWatcher(void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::System::AppDiagnosticInfoWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::DiagnosticAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestInfoForPackageAsync(void* packageFamilyName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoForPackageAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestInfoForAppAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoForAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestInfoForAppUserModelId(void* appUserModelId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoForAppAsync(*reinterpret_cast<hstring const*>(&appUserModelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfoWatcher> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfoWatcher>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppDiagnosticInfoWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppDiagnosticInfoWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppDiagnosticInfoWatcherEventArgs> : produce_base<D, winrt::Windows::System::IAppDiagnosticInfoWatcherEventArgs>
    {
        int32_t __stdcall get_AppDiagnosticInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppDiagnosticInfo>(this->shim().AppDiagnosticInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppExecutionStateChangeResult> : produce_base<D, winrt::Windows::System::IAppExecutionStateChangeResult>
    {
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
    struct produce<D, winrt::Windows::System::IAppMemoryReport> : produce_base<D, winrt::Windows::System::IAppMemoryReport>
    {
        int32_t __stdcall get_PrivateCommitUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().PrivateCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PeakPrivateCommitUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().PeakPrivateCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TotalCommitUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().TotalCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TotalCommitLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().TotalCommitLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppMemoryReport2> : produce_base<D, winrt::Windows::System::IAppMemoryReport2>
    {
        int32_t __stdcall get_ExpectedTotalCommitLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ExpectedTotalCommitLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs> : produce_base<D, winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs>
    {
        int32_t __stdcall get_OldLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().OldLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().NewLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupBackgroundTaskReport> : produce_base<D, winrt::Windows::System::IAppResourceGroupBackgroundTaskReport>
    {
        int32_t __stdcall get_TaskId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().TaskId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Trigger(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Trigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EntryPoint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EntryPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupInfo> : produce_base<D, winrt::Windows::System::IAppResourceGroupInfo>
    {
        int32_t __stdcall get_InstanceId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().InstanceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsShared(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsShared());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBackgroundTaskReports(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppResourceGroupBackgroundTaskReport>>(this->shim().GetBackgroundTaskReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMemoryReport(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppResourceGroupMemoryReport>(this->shim().GetMemoryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetProcessDiagnosticInfos(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo>>(this->shim().GetProcessDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStateReport(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppResourceGroupStateReport>(this->shim().GetStateReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupInfo2> : produce_base<D, winrt::Windows::System::IAppResourceGroupInfo2>
    {
        int32_t __stdcall StartSuspendAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>>(this->shim().StartSuspendAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartResumeAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>>(this->shim().StartResumeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartTerminateAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AppExecutionStateChangeResult>>(this->shim().StartTerminateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupInfoWatcher> : produce_base<D, winrt::Windows::System::IAppResourceGroupInfoWatcher>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ExecutionStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ExecutionStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::AppResourceGroupInfoWatcher, winrt::Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ExecutionStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExecutionStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Status(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::System::AppResourceGroupInfoWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs> : produce_base<D, winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs>
    {
        int32_t __stdcall get_AppDiagnosticInfos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::AppDiagnosticInfo>>(this->shim().AppDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppResourceGroupInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppResourceGroupInfo>(this->shim().AppResourceGroupInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs> : produce_base<D, winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs>
    {
        int32_t __stdcall get_AppDiagnosticInfos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::AppDiagnosticInfo>>(this->shim().AppDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppResourceGroupInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppResourceGroupInfo>(this->shim().AppResourceGroupInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupMemoryReport> : produce_base<D, winrt::Windows::System::IAppResourceGroupMemoryReport>
    {
        int32_t __stdcall get_CommitUsageLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().CommitUsageLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommitUsageLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppMemoryUsageLevel>(this->shim().CommitUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrivateCommitUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().PrivateCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TotalCommitUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().TotalCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppResourceGroupStateReport> : produce_base<D, winrt::Windows::System::IAppResourceGroupStateReport>
    {
        int32_t __stdcall get_ExecutionState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppResourceGroupExecutionState>(this->shim().ExecutionState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnergyQuotaState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppResourceGroupEnergyQuotaState>(this->shim().EnergyQuotaState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerHost> : produce_base<D, winrt::Windows::System::IAppUriHandlerHost>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerHost2> : produce_base<D, winrt::Windows::System::IAppUriHandlerHost2>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerHostFactory> : produce_base<D, winrt::Windows::System::IAppUriHandlerHostFactory>
    {
        int32_t __stdcall CreateInstance(void* name, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppUriHandlerHost>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerRegistration> : produce_base<D, winrt::Windows::System::IAppUriHandlerRegistration>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppAddedHostsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppUriHandlerHost>>>(this->shim().GetAppAddedHostsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAppAddedHostsAsync(void* hosts, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetAppAddedHostsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::System::AppUriHandlerHost> const*>(&hosts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerRegistration2> : produce_base<D, winrt::Windows::System::IAppUriHandlerRegistration2>
    {
        int32_t __stdcall GetAllHosts(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppUriHandlerHost>>(this->shim().GetAllHosts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateHosts(void* hosts) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateHosts(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::System::AppUriHandlerHost> const*>(&hosts));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerRegistrationManager> : produce_base<D, winrt::Windows::System::IAppUriHandlerRegistrationManager>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetRegistration(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppUriHandlerRegistration>(this->shim().TryGetRegistration(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerRegistrationManager2> : produce_base<D, winrt::Windows::System::IAppUriHandlerRegistrationManager2>
    {
        int32_t __stdcall get_PackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics> : produce_base<D, winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppUriHandlerRegistrationManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppUriHandlerRegistrationManager>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics2> : produce_base<D, winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics2>
    {
        int32_t __stdcall GetForPackage(void* packageFamilyName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppUriHandlerRegistrationManager>(this->shim().GetForPackage(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForPackageForUser(void* packageFamilyName, void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::AppUriHandlerRegistrationManager>(this->shim().GetForPackageForUser(*reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDateTimeSettingsStatics> : produce_base<D, winrt::Windows::System::IDateTimeSettingsStatics>
    {
        int32_t __stdcall SetSystemDateTime(int64_t utcDateTime) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSystemDateTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&utcDateTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueue> : produce_base<D, winrt::Windows::System::IDispatcherQueue>
    {
        int32_t __stdcall CreateTimer(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::DispatcherQueueTimer>(this->shim().CreateTimer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryEnqueue(void* callback, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryEnqueue(*reinterpret_cast<winrt::Windows::System::DispatcherQueueHandler const*>(&callback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryEnqueueWithPriority(int32_t priority, void* callback, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryEnqueue(*reinterpret_cast<winrt::Windows::System::DispatcherQueuePriority const*>(&priority), *reinterpret_cast<winrt::Windows::System::DispatcherQueueHandler const*>(&callback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ShutdownStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShutdownStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueue, winrt::Windows::System::DispatcherQueueShutdownStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShutdownStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShutdownStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ShutdownCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShutdownCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueue, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShutdownCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShutdownCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueue2> : produce_base<D, winrt::Windows::System::IDispatcherQueue2>
    {
        int32_t __stdcall get_HasThreadAccess(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasThreadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueueController> : produce_base<D, winrt::Windows::System::IDispatcherQueueController>
    {
        int32_t __stdcall get_DispatcherQueue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShutdownQueueAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ShutdownQueueAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueueControllerStatics> : produce_base<D, winrt::Windows::System::IDispatcherQueueControllerStatics>
    {
        int32_t __stdcall CreateOnDedicatedThread(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::DispatcherQueueController>(this->shim().CreateOnDedicatedThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueueShutdownStartingEventArgs> : produce_base<D, winrt::Windows::System::IDispatcherQueueShutdownStartingEventArgs>
    {
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueueStatics> : produce_base<D, winrt::Windows::System::IDispatcherQueueStatics>
    {
        int32_t __stdcall GetForCurrentThread(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::DispatcherQueue>(this->shim().GetForCurrentThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IDispatcherQueueTimer> : produce_base<D, winrt::Windows::System::IDispatcherQueueTimer>
    {
        int32_t __stdcall get_Interval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Interval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Interval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRunning(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRunning());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRepeating(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRepeating());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsRepeating(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRepeating(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Tick(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Tick(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::DispatcherQueueTimer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Tick(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tick(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IFolderLauncherOptions> : produce_base<D, winrt::Windows::System::IFolderLauncherOptions>
    {
        int32_t __stdcall get_ItemsToSelect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::IStorageItem>>(this->shim().ItemsToSelect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IKnownUserPropertiesStatics> : produce_base<D, winrt::Windows::System::IKnownUserPropertiesStatics>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LastName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccountName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AccountName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GuestHost(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GuestHost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrincipalName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PrincipalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DomainName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionInitiationProtocolUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SessionInitiationProtocolUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IKnownUserPropertiesStatics2> : produce_base<D, winrt::Windows::System::IKnownUserPropertiesStatics2>
    {
        int32_t __stdcall get_AgeEnforcementRegion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AgeEnforcementRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILaunchUriResult> : produce_base<D, winrt::Windows::System::ILaunchUriResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::LaunchUriStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Result(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherOptions> : produce_base<D, winrt::Windows::System::ILauncherOptions>
    {
        int32_t __stdcall get_TreatAsUntrusted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TreatAsUntrusted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TreatAsUntrusted(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TreatAsUntrusted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayApplicationPicker(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DisplayApplicationPicker());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayApplicationPicker(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayApplicationPicker(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UI(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::LauncherUIOptions>(this->shim().UI());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredApplicationPackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PreferredApplicationPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferredApplicationPackageFamilyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferredApplicationPackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredApplicationDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PreferredApplicationDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferredApplicationDisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferredApplicationDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FallbackUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().FallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FallbackUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FallbackUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentType(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherOptions2> : produce_base<D, winrt::Windows::System::ILauncherOptions2>
    {
        int32_t __stdcall get_TargetApplicationPackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetApplicationPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetApplicationPackageFamilyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetApplicationPackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NeighboringFilesQuery(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Search::StorageFileQueryResult>(this->shim().NeighboringFilesQuery());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NeighboringFilesQuery(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NeighboringFilesQuery(*reinterpret_cast<winrt::Windows::Storage::Search::StorageFileQueryResult const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherOptions3> : produce_base<D, winrt::Windows::System::ILauncherOptions3>
    {
        int32_t __stdcall get_IgnoreAppUriHandlers(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IgnoreAppUriHandlers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IgnoreAppUriHandlers(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IgnoreAppUriHandlers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherOptions4> : produce_base<D, winrt::Windows::System::ILauncherOptions4>
    {
        int32_t __stdcall get_LimitPickerToCurrentAppAndAppUriHandlers(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().LimitPickerToCurrentAppAndAppUriHandlers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LimitPickerToCurrentAppAndAppUriHandlers(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LimitPickerToCurrentAppAndAppUriHandlers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherStatics> : produce_base<D, winrt::Windows::System::ILauncherStatics>
    {
        int32_t __stdcall LaunchFileAsync(void* file, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFileWithOptionsAsync(void* file, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchUriAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriWithOptionsAsync(void* uri, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchUriAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherStatics2> : produce_base<D, winrt::Windows::System::ILauncherStatics2>
    {
        int32_t __stdcall LaunchUriForResultsAsync(void* uri, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriForResultsWithDataAsync(void* uri, void* options, void* inputData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriWithDataAsync(void* uri, void* options, void* inputData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchUriAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall QueryUriSupportAsync(void* uri, int32_t launchQuerySupportType, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryUriSupportAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LaunchQuerySupportType const*>(&launchQuerySupportType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall QueryUriSupportWithPackageFamilyNameAsync(void* uri, int32_t launchQuerySupportType, void* packageFamilyName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryUriSupportAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LaunchQuerySupportType const*>(&launchQuerySupportType), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall QueryFileSupportAsync(void* file, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryFileSupportAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall QueryFileSupportWithPackageFamilyNameAsync(void* file, void* packageFamilyName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryFileSupportAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&file), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindUriSchemeHandlersAsync(void* scheme, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>>(this->shim().FindUriSchemeHandlersAsync(*reinterpret_cast<hstring const*>(&scheme)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindUriSchemeHandlersWithLaunchUriTypeAsync(void* scheme, int32_t launchQuerySupportType, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>>(this->shim().FindUriSchemeHandlersAsync(*reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<winrt::Windows::System::LaunchQuerySupportType const*>(&launchQuerySupportType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindFileHandlersAsync(void* extension, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>>(this->shim().FindFileHandlersAsync(*reinterpret_cast<hstring const*>(&extension)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherStatics3> : produce_base<D, winrt::Windows::System::ILauncherStatics3>
    {
        int32_t __stdcall LaunchFolderAsync(void* folder, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFolderWithOptionsAsync(void* folder, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&folder), *reinterpret_cast<winrt::Windows::System::FolderLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherStatics4> : produce_base<D, winrt::Windows::System::ILauncherStatics4>
    {
        int32_t __stdcall QueryAppUriSupportAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryAppUriSupportAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall QueryAppUriSupportWithPackageFamilyNameAsync(void* uri, void* packageFamilyName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryAppUriSupportAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAppUriHandlersAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>>(this->shim().FindAppUriHandlersAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriForUserAsync(void* user, void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>>(this->shim().LaunchUriForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriWithOptionsForUserAsync(void* user, void* uri, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>>(this->shim().LaunchUriForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriWithDataForUserAsync(void* user, void* uri, void* options, void* inputData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriStatus>>(this->shim().LaunchUriForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriForResultsForUserAsync(void* user, void* uri, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriForResultsWithDataForUserAsync(void* user, void* uri, void* options, void* inputData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherStatics5> : produce_base<D, winrt::Windows::System::ILauncherStatics5>
    {
        int32_t __stdcall LaunchFolderPathAsync(void* path, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathAsync(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFolderPathWithOptionsAsync(void* path, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathAsync(*reinterpret_cast<hstring const*>(&path), *reinterpret_cast<winrt::Windows::System::FolderLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFolderPathForUserAsync(void* user, void* path, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchFolderPathWithOptionsForUserAsync(void* user, void* path, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&path), *reinterpret_cast<winrt::Windows::System::FolderLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherUIOptions> : produce_base<D, winrt::Windows::System::ILauncherUIOptions>
    {
        int32_t __stdcall get_InvocationPoint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().InvocationPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InvocationPoint(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InvocationPoint(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionRect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>>(this->shim().SelectionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionRect(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionRect(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredPlacement(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Popups::Placement>(this->shim().PreferredPlacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferredPlacement(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferredPlacement(*reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::System::ILauncherViewOptions> : produce_base<D, winrt::Windows::System::ILauncherViewOptions>
    {
        int32_t __stdcall get_DesiredRemainingView(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::ViewManagement::ViewSizePreference>(this->shim().DesiredRemainingView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredRemainingView(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredRemainingView(*reinterpret_cast<winrt::Windows::UI::ViewManagement::ViewSizePreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IMemoryManagerStatics> : produce_base<D, winrt::Windows::System::IMemoryManagerStatics>
    {
        int32_t __stdcall get_AppMemoryUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().AppMemoryUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppMemoryUsageLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().AppMemoryUsageLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppMemoryUsageLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::AppMemoryUsageLevel>(this->shim().AppMemoryUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AppMemoryUsageIncreased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AppMemoryUsageIncreased(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AppMemoryUsageIncreased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppMemoryUsageIncreased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AppMemoryUsageDecreased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AppMemoryUsageDecreased(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AppMemoryUsageDecreased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppMemoryUsageDecreased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AppMemoryUsageLimitChanging(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AppMemoryUsageLimitChanging(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AppMemoryUsageLimitChanging(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppMemoryUsageLimitChanging(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IMemoryManagerStatics2> : produce_base<D, winrt::Windows::System::IMemoryManagerStatics2>
    {
        int32_t __stdcall GetAppMemoryReport(void** memoryReport) noexcept final try
        {
            clear_abi(memoryReport);
            typename D::abi_guard guard(this->shim());
            *memoryReport = detach_from<winrt::Windows::System::AppMemoryReport>(this->shim().GetAppMemoryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetProcessMemoryReport(void** memoryReport) noexcept final try
        {
            clear_abi(memoryReport);
            typename D::abi_guard guard(this->shim());
            *memoryReport = detach_from<winrt::Windows::System::ProcessMemoryReport>(this->shim().GetProcessMemoryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IMemoryManagerStatics3> : produce_base<D, winrt::Windows::System::IMemoryManagerStatics3>
    {
        int32_t __stdcall TrySetAppMemoryUsageLimit(uint64_t value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySetAppMemoryUsageLimit(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IMemoryManagerStatics4> : produce_base<D, winrt::Windows::System::IMemoryManagerStatics4>
    {
        int32_t __stdcall get_ExpectedAppMemoryUsageLimit(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ExpectedAppMemoryUsageLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IProcessLauncherOptions> : produce_base<D, winrt::Windows::System::IProcessLauncherOptions>
    {
        int32_t __stdcall get_StandardInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().StandardInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StandardInput(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StandardInput(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StandardOutput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().StandardOutput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StandardOutput(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StandardOutput(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StandardError(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().StandardError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StandardError(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StandardError(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WorkingDirectory(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WorkingDirectory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WorkingDirectory(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WorkingDirectory(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IProcessLauncherResult> : produce_base<D, winrt::Windows::System::IProcessLauncherResult>
    {
        int32_t __stdcall get_ExitCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExitCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IProcessLauncherStatics> : produce_base<D, winrt::Windows::System::IProcessLauncherStatics>
    {
        int32_t __stdcall RunToCompletionAsync(void* fileName, void* args, void** asyncOperationResult) noexcept final try
        {
            clear_abi(asyncOperationResult);
            typename D::abi_guard guard(this->shim());
            *asyncOperationResult = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::ProcessLauncherResult>>(this->shim().RunToCompletionAsync(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<hstring const*>(&args)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RunToCompletionAsyncWithOptions(void* fileName, void* args, void* options, void** asyncOperationResult) noexcept final try
        {
            clear_abi(asyncOperationResult);
            typename D::abi_guard guard(this->shim());
            *asyncOperationResult = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::ProcessLauncherResult>>(this->shim().RunToCompletionAsync(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<hstring const*>(&args), *reinterpret_cast<winrt::Windows::System::ProcessLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IProcessMemoryReport> : produce_base<D, winrt::Windows::System::IProcessMemoryReport>
    {
        int32_t __stdcall get_PrivateWorkingSetUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().PrivateWorkingSetUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TotalWorkingSetUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().TotalWorkingSetUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IProtocolForResultsOperation> : produce_base<D, winrt::Windows::System::IProtocolForResultsOperation>
    {
        int32_t __stdcall ReportCompleted(void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IRemoteLauncherOptions> : produce_base<D, winrt::Windows::System::IRemoteLauncherOptions>
    {
        int32_t __stdcall get_FallbackUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().FallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FallbackUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FallbackUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredAppIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().PreferredAppIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IRemoteLauncherStatics> : produce_base<D, winrt::Windows::System::IRemoteLauncherStatics>
    {
        int32_t __stdcall LaunchUriAsync(void* remoteSystemConnectionRequest, void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>>(this->shim().LaunchUriAsync(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriWithOptionsAsync(void* remoteSystemConnectionRequest, void* uri, void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>>(this->shim().LaunchUriAsync(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::RemoteLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LaunchUriWithDataAsync(void* remoteSystemConnectionRequest, void* uri, void* options, void* inputData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteLaunchUriStatus>>(this->shim().LaunchUriAsync(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::System::RemoteLauncherOptions const*>(&options), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IShutdownManagerStatics> : produce_base<D, winrt::Windows::System::IShutdownManagerStatics>
    {
        int32_t __stdcall BeginShutdown(int32_t shutdownKind, int64_t timeout) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeginShutdown(*reinterpret_cast<winrt::Windows::System::ShutdownKind const*>(&shutdownKind), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timeout));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CancelShutdown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CancelShutdown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IShutdownManagerStatics2> : produce_base<D, winrt::Windows::System::IShutdownManagerStatics2>
    {
        int32_t __stdcall IsPowerStateSupported(int32_t powerState, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPowerStateSupported(*reinterpret_cast<winrt::Windows::System::PowerState const*>(&powerState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnterPowerState(int32_t powerState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnterPowerState(*reinterpret_cast<winrt::Windows::System::PowerState const*>(&powerState));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnterPowerStateWithTimeSpan(int32_t powerState, int64_t wakeUpAfter) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnterPowerState(*reinterpret_cast<winrt::Windows::System::PowerState const*>(&powerState), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&wakeUpAfter));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ITimeZoneSettingsStatics> : produce_base<D, winrt::Windows::System::ITimeZoneSettingsStatics>
    {
        int32_t __stdcall get_CurrentTimeZoneDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CurrentTimeZoneDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedTimeZoneDisplayNames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedTimeZoneDisplayNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanChangeTimeZone(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanChangeTimeZone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangeTimeZoneByDisplayName(void* timeZoneDisplayName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangeTimeZoneByDisplayName(*reinterpret_cast<hstring const*>(&timeZoneDisplayName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::ITimeZoneSettingsStatics2> : produce_base<D, winrt::Windows::System::ITimeZoneSettingsStatics2>
    {
        int32_t __stdcall AutoUpdateTimeZoneAsync(int64_t timeout, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::AutoUpdateTimeZoneStatus>>(this->shim().AutoUpdateTimeZoneAsync(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUser> : produce_base<D, winrt::Windows::System::IUser>
    {
        int32_t __stdcall get_NonRoamableId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NonRoamableId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::UserAuthenticationStatus>(this->shim().AuthenticationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::UserType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPropertyAsync(void* value, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable>>(this->shim().GetPropertyAsync(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPropertiesAsync(void* values, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IPropertySet>>(this->shim().GetPropertiesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPictureAsync(int32_t desiredSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>>(this->shim().GetPictureAsync(*reinterpret_cast<winrt::Windows::System::UserPictureSize const*>(&desiredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUser2> : produce_base<D, winrt::Windows::System::IUser2>
    {
        int32_t __stdcall CheckUserAgeConsentGroupAsync(int32_t consentGroup, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::UserAgeConsentResult>>(this->shim().CheckUserAgeConsentGroupAsync(*reinterpret_cast<winrt::Windows::System::UserAgeConsentGroup const*>(&consentGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserAuthenticationStatusChangeDeferral> : produce_base<D, winrt::Windows::System::IUserAuthenticationStatusChangeDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs> : produce_base<D, winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs>
    {
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::UserAuthenticationStatusChangeDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::UserAuthenticationStatus>(this->shim().NewStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::UserAuthenticationStatus>(this->shim().CurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserChangedEventArgs> : produce_base<D, winrt::Windows::System::IUserChangedEventArgs>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserChangedEventArgs2> : produce_base<D, winrt::Windows::System::IUserChangedEventArgs2>
    {
        int32_t __stdcall get_ChangedPropertyKinds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::UserWatcherUpdateKind>>(this->shim().ChangedPropertyKinds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserDeviceAssociationChangedEventArgs> : produce_base<D, winrt::Windows::System::IUserDeviceAssociationChangedEventArgs>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewUser(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().NewUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OldUser(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().OldUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserDeviceAssociationStatics> : produce_base<D, winrt::Windows::System::IUserDeviceAssociationStatics>
    {
        int32_t __stdcall FindUserFromDeviceId(void* deviceId, void** user) noexcept final try
        {
            clear_abi(user);
            typename D::abi_guard guard(this->shim());
            *user = detach_from<winrt::Windows::System::User>(this->shim().FindUserFromDeviceId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_UserDeviceAssociationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UserDeviceAssociationChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UserDeviceAssociationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserDeviceAssociationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserPicker> : produce_base<D, winrt::Windows::System::IUserPicker>
    {
        int32_t __stdcall get_AllowGuestAccounts(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowGuestAccounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowGuestAccounts(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowGuestAccounts(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuggestedSelectedUser(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().SuggestedSelectedUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuggestedSelectedUser(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestedSelectedUser(*reinterpret_cast<winrt::Windows::System::User const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleUserAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::User>>(this->shim().PickSingleUserAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserPickerStatics> : produce_base<D, winrt::Windows::System::IUserPickerStatics>
    {
        int32_t __stdcall IsSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserStatics> : produce_base<D, winrt::Windows::System::IUserStatics>
    {
        int32_t __stdcall CreateWatcher(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::UserWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncByType(int32_t type, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>>(this->shim().FindAllAsync(*reinterpret_cast<winrt::Windows::System::UserType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncByTypeAndStatus(int32_t type, int32_t status, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>>(this->shim().FindAllAsync(*reinterpret_cast<winrt::Windows::System::UserType const*>(&type), *reinterpret_cast<winrt::Windows::System::UserAuthenticationStatus const*>(&status)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFromId(void* nonRoamableId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::User>(this->shim().GetFromId(*reinterpret_cast<hstring const*>(&nonRoamableId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserStatics2> : produce_base<D, winrt::Windows::System::IUserStatics2>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::User>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::IUserWatcher> : produce_base<D, winrt::Windows::System::IUserWatcher>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::UserWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AuthenticationStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AuthenticationStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AuthenticationStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthenticationStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AuthenticationStatusChanging(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AuthenticationStatusChanging(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::System::UserAuthenticationStatusChangingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AuthenticationStatusChanging(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthenticationStatusChanging(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::UserWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System
{
    constexpr auto operator|(VirtualKeyModifiers const left, VirtualKeyModifiers const right) noexcept
    {
        return static_cast<VirtualKeyModifiers>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(VirtualKeyModifiers& left, VirtualKeyModifiers const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(VirtualKeyModifiers const left, VirtualKeyModifiers const right) noexcept
    {
        return static_cast<VirtualKeyModifiers>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(VirtualKeyModifiers& left, VirtualKeyModifiers const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(VirtualKeyModifiers const value) noexcept
    {
        return static_cast<VirtualKeyModifiers>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(VirtualKeyModifiers const left, VirtualKeyModifiers const right) noexcept
    {
        return static_cast<VirtualKeyModifiers>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(VirtualKeyModifiers& left, VirtualKeyModifiers const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto AppDiagnosticInfo::RequestInfoAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>(*)(IAppDiagnosticInfoStatics const&), AppDiagnosticInfo, IAppDiagnosticInfoStatics>([](IAppDiagnosticInfoStatics const& f) { return f.RequestInfoAsync(); });
    }
    inline auto AppDiagnosticInfo::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::System::AppDiagnosticInfoWatcher(*)(IAppDiagnosticInfoStatics2 const&), AppDiagnosticInfo, IAppDiagnosticInfoStatics2>([](IAppDiagnosticInfoStatics2 const& f) { return f.CreateWatcher(); });
    }
    inline auto AppDiagnosticInfo::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::DiagnosticAccessStatus>(*)(IAppDiagnosticInfoStatics2 const&), AppDiagnosticInfo, IAppDiagnosticInfoStatics2>([](IAppDiagnosticInfoStatics2 const& f) { return f.RequestAccessAsync(); });
    }
    inline auto AppDiagnosticInfo::RequestInfoForPackageAsync(param::hstring const& packageFamilyName)
    {
        return impl::call_factory<AppDiagnosticInfo, IAppDiagnosticInfoStatics2>([&](IAppDiagnosticInfoStatics2 const& f) { return f.RequestInfoForPackageAsync(packageFamilyName); });
    }
    inline auto AppDiagnosticInfo::RequestInfoForAppAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::AppDiagnosticInfo>>(*)(IAppDiagnosticInfoStatics2 const&), AppDiagnosticInfo, IAppDiagnosticInfoStatics2>([](IAppDiagnosticInfoStatics2 const& f) { return f.RequestInfoForAppAsync(); });
    }
    inline auto AppDiagnosticInfo::RequestInfoForAppAsync(param::hstring const& appUserModelId)
    {
        return impl::call_factory<AppDiagnosticInfo, IAppDiagnosticInfoStatics2>([&](IAppDiagnosticInfoStatics2 const& f) { return f.RequestInfoForAppAsync(appUserModelId); });
    }
    inline AppUriHandlerHost::AppUriHandlerHost() :
        AppUriHandlerHost(impl::call_factory_cast<AppUriHandlerHost(*)(winrt::Windows::Foundation::IActivationFactory const&), AppUriHandlerHost>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppUriHandlerHost>(); }))
    {
    }
    inline AppUriHandlerHost::AppUriHandlerHost(param::hstring const& name) :
        AppUriHandlerHost(impl::call_factory<AppUriHandlerHost, IAppUriHandlerHostFactory>([&](IAppUriHandlerHostFactory const& f) { return f.CreateInstance(name); }))
    {
    }
    inline auto AppUriHandlerRegistrationManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::System::AppUriHandlerRegistrationManager(*)(IAppUriHandlerRegistrationManagerStatics const&), AppUriHandlerRegistrationManager, IAppUriHandlerRegistrationManagerStatics>([](IAppUriHandlerRegistrationManagerStatics const& f) { return f.GetDefault(); });
    }
    inline auto AppUriHandlerRegistrationManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<AppUriHandlerRegistrationManager, IAppUriHandlerRegistrationManagerStatics>([&](IAppUriHandlerRegistrationManagerStatics const& f) { return f.GetForUser(user); });
    }
    inline auto AppUriHandlerRegistrationManager::GetForPackage(param::hstring const& packageFamilyName)
    {
        return impl::call_factory<AppUriHandlerRegistrationManager, IAppUriHandlerRegistrationManagerStatics2>([&](IAppUriHandlerRegistrationManagerStatics2 const& f) { return f.GetForPackage(packageFamilyName); });
    }
    inline auto AppUriHandlerRegistrationManager::GetForPackageForUser(param::hstring const& packageFamilyName, winrt::Windows::System::User const& user)
    {
        return impl::call_factory<AppUriHandlerRegistrationManager, IAppUriHandlerRegistrationManagerStatics2>([&](IAppUriHandlerRegistrationManagerStatics2 const& f) { return f.GetForPackageForUser(packageFamilyName, user); });
    }
    inline auto DateTimeSettings::SetSystemDateTime(winrt::Windows::Foundation::DateTime const& utcDateTime)
    {
        impl::call_factory<DateTimeSettings, IDateTimeSettingsStatics>([&](IDateTimeSettingsStatics const& f) { return f.SetSystemDateTime(utcDateTime); });
    }
    inline auto DispatcherQueue::GetForCurrentThread()
    {
        return impl::call_factory_cast<winrt::Windows::System::DispatcherQueue(*)(IDispatcherQueueStatics const&), DispatcherQueue, IDispatcherQueueStatics>([](IDispatcherQueueStatics const& f) { return f.GetForCurrentThread(); });
    }
    inline auto DispatcherQueueController::CreateOnDedicatedThread()
    {
        return impl::call_factory_cast<winrt::Windows::System::DispatcherQueueController(*)(IDispatcherQueueControllerStatics const&), DispatcherQueueController, IDispatcherQueueControllerStatics>([](IDispatcherQueueControllerStatics const& f) { return f.CreateOnDedicatedThread(); });
    }
    inline FolderLauncherOptions::FolderLauncherOptions() :
        FolderLauncherOptions(impl::call_factory_cast<FolderLauncherOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), FolderLauncherOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FolderLauncherOptions>(); }))
    {
    }
    inline auto KnownUserProperties::DisplayName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.DisplayName(); });
    }
    inline auto KnownUserProperties::FirstName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.FirstName(); });
    }
    inline auto KnownUserProperties::LastName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.LastName(); });
    }
    inline auto KnownUserProperties::ProviderName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.ProviderName(); });
    }
    inline auto KnownUserProperties::AccountName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.AccountName(); });
    }
    inline auto KnownUserProperties::GuestHost()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.GuestHost(); });
    }
    inline auto KnownUserProperties::PrincipalName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.PrincipalName(); });
    }
    inline auto KnownUserProperties::DomainName()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.DomainName(); });
    }
    inline auto KnownUserProperties::SessionInitiationProtocolUri()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics const&), KnownUserProperties, IKnownUserPropertiesStatics>([](IKnownUserPropertiesStatics const& f) { return f.SessionInitiationProtocolUri(); });
    }
    inline auto KnownUserProperties::AgeEnforcementRegion()
    {
        return impl::call_factory_cast<hstring(*)(IKnownUserPropertiesStatics2 const&), KnownUserProperties, IKnownUserPropertiesStatics2>([](IKnownUserPropertiesStatics2 const& f) { return f.AgeEnforcementRegion(); });
    }
    inline auto Launcher::LaunchFileAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<Launcher, ILauncherStatics>([&](ILauncherStatics const& f) { return f.LaunchFileAsync(file); });
    }
    inline auto Launcher::LaunchFileAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::System::LauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics>([&](ILauncherStatics const& f) { return f.LaunchFileAsync(file, options); });
    }
    inline auto Launcher::LaunchUriAsync(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<Launcher, ILauncherStatics>([&](ILauncherStatics const& f) { return f.LaunchUriAsync(uri); });
    }
    inline auto Launcher::LaunchUriAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics>([&](ILauncherStatics const& f) { return f.LaunchUriAsync(uri, options); });
    }
    inline auto Launcher::LaunchUriForResultsAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.LaunchUriForResultsAsync(uri, options); });
    }
    inline auto Launcher::LaunchUriForResultsAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.LaunchUriForResultsAsync(uri, options, inputData); });
    }
    inline auto Launcher::LaunchUriAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.LaunchUriAsync(uri, options, inputData); });
    }
    inline auto Launcher::QueryUriSupportAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LaunchQuerySupportType const& launchQuerySupportType)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.QueryUriSupportAsync(uri, launchQuerySupportType); });
    }
    inline auto Launcher::QueryUriSupportAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LaunchQuerySupportType const& launchQuerySupportType, param::hstring const& packageFamilyName)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.QueryUriSupportAsync(uri, launchQuerySupportType, packageFamilyName); });
    }
    inline auto Launcher::QueryFileSupportAsync(winrt::Windows::Storage::StorageFile const& file)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.QueryFileSupportAsync(file); });
    }
    inline auto Launcher::QueryFileSupportAsync(winrt::Windows::Storage::StorageFile const& file, param::hstring const& packageFamilyName)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.QueryFileSupportAsync(file, packageFamilyName); });
    }
    inline auto Launcher::FindUriSchemeHandlersAsync(param::hstring const& scheme)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.FindUriSchemeHandlersAsync(scheme); });
    }
    inline auto Launcher::FindUriSchemeHandlersAsync(param::hstring const& scheme, winrt::Windows::System::LaunchQuerySupportType const& launchQuerySupportType)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.FindUriSchemeHandlersAsync(scheme, launchQuerySupportType); });
    }
    inline auto Launcher::FindFileHandlersAsync(param::hstring const& extension)
    {
        return impl::call_factory<Launcher, ILauncherStatics2>([&](ILauncherStatics2 const& f) { return f.FindFileHandlersAsync(extension); });
    }
    inline auto Launcher::LaunchFolderAsync(winrt::Windows::Storage::IStorageFolder const& folder)
    {
        return impl::call_factory<Launcher, ILauncherStatics3>([&](ILauncherStatics3 const& f) { return f.LaunchFolderAsync(folder); });
    }
    inline auto Launcher::LaunchFolderAsync(winrt::Windows::Storage::IStorageFolder const& folder, winrt::Windows::System::FolderLauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics3>([&](ILauncherStatics3 const& f) { return f.LaunchFolderAsync(folder, options); });
    }
    inline auto Launcher::QueryAppUriSupportAsync(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.QueryAppUriSupportAsync(uri); });
    }
    inline auto Launcher::QueryAppUriSupportAsync(winrt::Windows::Foundation::Uri const& uri, param::hstring const& packageFamilyName)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.QueryAppUriSupportAsync(uri, packageFamilyName); });
    }
    inline auto Launcher::FindAppUriHandlersAsync(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.FindAppUriHandlersAsync(uri); });
    }
    inline auto Launcher::LaunchUriForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.LaunchUriForUserAsync(user, uri); });
    }
    inline auto Launcher::LaunchUriForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.LaunchUriForUserAsync(user, uri, options); });
    }
    inline auto Launcher::LaunchUriForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.LaunchUriForUserAsync(user, uri, options, inputData); });
    }
    inline auto Launcher::LaunchUriForResultsForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.LaunchUriForResultsForUserAsync(user, uri, options); });
    }
    inline auto Launcher::LaunchUriForResultsForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::LauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData)
    {
        return impl::call_factory<Launcher, ILauncherStatics4>([&](ILauncherStatics4 const& f) { return f.LaunchUriForResultsForUserAsync(user, uri, options, inputData); });
    }
    inline auto Launcher::LaunchFolderPathAsync(param::hstring const& path)
    {
        return impl::call_factory<Launcher, ILauncherStatics5>([&](ILauncherStatics5 const& f) { return f.LaunchFolderPathAsync(path); });
    }
    inline auto Launcher::LaunchFolderPathAsync(param::hstring const& path, winrt::Windows::System::FolderLauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics5>([&](ILauncherStatics5 const& f) { return f.LaunchFolderPathAsync(path, options); });
    }
    inline auto Launcher::LaunchFolderPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path)
    {
        return impl::call_factory<Launcher, ILauncherStatics5>([&](ILauncherStatics5 const& f) { return f.LaunchFolderPathForUserAsync(user, path); });
    }
    inline auto Launcher::LaunchFolderPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path, winrt::Windows::System::FolderLauncherOptions const& options)
    {
        return impl::call_factory<Launcher, ILauncherStatics5>([&](ILauncherStatics5 const& f) { return f.LaunchFolderPathForUserAsync(user, path, options); });
    }
    inline LauncherOptions::LauncherOptions() :
        LauncherOptions(impl::call_factory_cast<LauncherOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), LauncherOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LauncherOptions>(); }))
    {
    }
    inline auto MemoryManager::AppMemoryUsage()
    {
        return impl::call_factory_cast<uint64_t(*)(IMemoryManagerStatics const&), MemoryManager, IMemoryManagerStatics>([](IMemoryManagerStatics const& f) { return f.AppMemoryUsage(); });
    }
    inline auto MemoryManager::AppMemoryUsageLimit()
    {
        return impl::call_factory_cast<uint64_t(*)(IMemoryManagerStatics const&), MemoryManager, IMemoryManagerStatics>([](IMemoryManagerStatics const& f) { return f.AppMemoryUsageLimit(); });
    }
    inline auto MemoryManager::AppMemoryUsageLevel()
    {
        return impl::call_factory_cast<winrt::Windows::System::AppMemoryUsageLevel(*)(IMemoryManagerStatics const&), MemoryManager, IMemoryManagerStatics>([](IMemoryManagerStatics const& f) { return f.AppMemoryUsageLevel(); });
    }
    inline auto MemoryManager::AppMemoryUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MemoryManager, IMemoryManagerStatics>([&](IMemoryManagerStatics const& f) { return f.AppMemoryUsageIncreased(handler); });
    }
    inline MemoryManager::AppMemoryUsageIncreased_revoker MemoryManager::AppMemoryUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MemoryManager, winrt::Windows::System::IMemoryManagerStatics>();
        return { f, f.AppMemoryUsageIncreased(handler) };
    }
    inline auto MemoryManager::AppMemoryUsageIncreased(winrt::event_token const& token)
    {
        impl::call_factory<MemoryManager, IMemoryManagerStatics>([&](IMemoryManagerStatics const& f) { return f.AppMemoryUsageIncreased(token); });
    }
    inline auto MemoryManager::AppMemoryUsageDecreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MemoryManager, IMemoryManagerStatics>([&](IMemoryManagerStatics const& f) { return f.AppMemoryUsageDecreased(handler); });
    }
    inline MemoryManager::AppMemoryUsageDecreased_revoker MemoryManager::AppMemoryUsageDecreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MemoryManager, winrt::Windows::System::IMemoryManagerStatics>();
        return { f, f.AppMemoryUsageDecreased(handler) };
    }
    inline auto MemoryManager::AppMemoryUsageDecreased(winrt::event_token const& token)
    {
        impl::call_factory<MemoryManager, IMemoryManagerStatics>([&](IMemoryManagerStatics const& f) { return f.AppMemoryUsageDecreased(token); });
    }
    inline auto MemoryManager::AppMemoryUsageLimitChanging(winrt::Windows::Foundation::EventHandler<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler)
    {
        return impl::call_factory<MemoryManager, IMemoryManagerStatics>([&](IMemoryManagerStatics const& f) { return f.AppMemoryUsageLimitChanging(handler); });
    }
    inline MemoryManager::AppMemoryUsageLimitChanging_revoker MemoryManager::AppMemoryUsageLimitChanging(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler)
    {
        auto f = get_activation_factory<MemoryManager, winrt::Windows::System::IMemoryManagerStatics>();
        return { f, f.AppMemoryUsageLimitChanging(handler) };
    }
    inline auto MemoryManager::AppMemoryUsageLimitChanging(winrt::event_token const& token)
    {
        impl::call_factory<MemoryManager, IMemoryManagerStatics>([&](IMemoryManagerStatics const& f) { return f.AppMemoryUsageLimitChanging(token); });
    }
    inline auto MemoryManager::GetAppMemoryReport()
    {
        return impl::call_factory_cast<winrt::Windows::System::AppMemoryReport(*)(IMemoryManagerStatics2 const&), MemoryManager, IMemoryManagerStatics2>([](IMemoryManagerStatics2 const& f) { return f.GetAppMemoryReport(); });
    }
    inline auto MemoryManager::GetProcessMemoryReport()
    {
        return impl::call_factory_cast<winrt::Windows::System::ProcessMemoryReport(*)(IMemoryManagerStatics2 const&), MemoryManager, IMemoryManagerStatics2>([](IMemoryManagerStatics2 const& f) { return f.GetProcessMemoryReport(); });
    }
    inline auto MemoryManager::TrySetAppMemoryUsageLimit(uint64_t value)
    {
        return impl::call_factory<MemoryManager, IMemoryManagerStatics3>([&](IMemoryManagerStatics3 const& f) { return f.TrySetAppMemoryUsageLimit(value); });
    }
    inline auto MemoryManager::ExpectedAppMemoryUsageLimit()
    {
        return impl::call_factory_cast<uint64_t(*)(IMemoryManagerStatics4 const&), MemoryManager, IMemoryManagerStatics4>([](IMemoryManagerStatics4 const& f) { return f.ExpectedAppMemoryUsageLimit(); });
    }
    inline auto ProcessLauncher::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args)
    {
        return impl::call_factory<ProcessLauncher, IProcessLauncherStatics>([&](IProcessLauncherStatics const& f) { return f.RunToCompletionAsync(fileName, args); });
    }
    inline auto ProcessLauncher::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args, winrt::Windows::System::ProcessLauncherOptions const& options)
    {
        return impl::call_factory<ProcessLauncher, IProcessLauncherStatics>([&](IProcessLauncherStatics const& f) { return f.RunToCompletionAsync(fileName, args, options); });
    }
    inline ProcessLauncherOptions::ProcessLauncherOptions() :
        ProcessLauncherOptions(impl::call_factory_cast<ProcessLauncherOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), ProcessLauncherOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ProcessLauncherOptions>(); }))
    {
    }
    inline auto RemoteLauncher::LaunchUriAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<RemoteLauncher, IRemoteLauncherStatics>([&](IRemoteLauncherStatics const& f) { return f.LaunchUriAsync(remoteSystemConnectionRequest, uri); });
    }
    inline auto RemoteLauncher::LaunchUriAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::RemoteLauncherOptions const& options)
    {
        return impl::call_factory<RemoteLauncher, IRemoteLauncherStatics>([&](IRemoteLauncherStatics const& f) { return f.LaunchUriAsync(remoteSystemConnectionRequest, uri, options); });
    }
    inline auto RemoteLauncher::LaunchUriAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::System::RemoteLauncherOptions const& options, winrt::Windows::Foundation::Collections::ValueSet const& inputData)
    {
        return impl::call_factory<RemoteLauncher, IRemoteLauncherStatics>([&](IRemoteLauncherStatics const& f) { return f.LaunchUriAsync(remoteSystemConnectionRequest, uri, options, inputData); });
    }
    inline RemoteLauncherOptions::RemoteLauncherOptions() :
        RemoteLauncherOptions(impl::call_factory_cast<RemoteLauncherOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), RemoteLauncherOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RemoteLauncherOptions>(); }))
    {
    }
    inline auto ShutdownManager::BeginShutdown(winrt::Windows::System::ShutdownKind const& shutdownKind, winrt::Windows::Foundation::TimeSpan const& timeout)
    {
        impl::call_factory<ShutdownManager, IShutdownManagerStatics>([&](IShutdownManagerStatics const& f) { return f.BeginShutdown(shutdownKind, timeout); });
    }
    inline auto ShutdownManager::CancelShutdown()
    {
        impl::call_factory_cast<void(*)(IShutdownManagerStatics const&), ShutdownManager, IShutdownManagerStatics>([](IShutdownManagerStatics const& f) { return f.CancelShutdown(); });
    }
    inline auto ShutdownManager::IsPowerStateSupported(winrt::Windows::System::PowerState const& powerState)
    {
        return impl::call_factory<ShutdownManager, IShutdownManagerStatics2>([&](IShutdownManagerStatics2 const& f) { return f.IsPowerStateSupported(powerState); });
    }
    inline auto ShutdownManager::EnterPowerState(winrt::Windows::System::PowerState const& powerState)
    {
        impl::call_factory<ShutdownManager, IShutdownManagerStatics2>([&](IShutdownManagerStatics2 const& f) { return f.EnterPowerState(powerState); });
    }
    inline auto ShutdownManager::EnterPowerState(winrt::Windows::System::PowerState const& powerState, winrt::Windows::Foundation::TimeSpan const& wakeUpAfter)
    {
        impl::call_factory<ShutdownManager, IShutdownManagerStatics2>([&](IShutdownManagerStatics2 const& f) { return f.EnterPowerState(powerState, wakeUpAfter); });
    }
    inline auto TimeZoneSettings::CurrentTimeZoneDisplayName()
    {
        return impl::call_factory_cast<hstring(*)(ITimeZoneSettingsStatics const&), TimeZoneSettings, ITimeZoneSettingsStatics>([](ITimeZoneSettingsStatics const& f) { return f.CurrentTimeZoneDisplayName(); });
    }
    inline auto TimeZoneSettings::SupportedTimeZoneDisplayNames()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring>(*)(ITimeZoneSettingsStatics const&), TimeZoneSettings, ITimeZoneSettingsStatics>([](ITimeZoneSettingsStatics const& f) { return f.SupportedTimeZoneDisplayNames(); });
    }
    inline auto TimeZoneSettings::CanChangeTimeZone()
    {
        return impl::call_factory_cast<bool(*)(ITimeZoneSettingsStatics const&), TimeZoneSettings, ITimeZoneSettingsStatics>([](ITimeZoneSettingsStatics const& f) { return f.CanChangeTimeZone(); });
    }
    inline auto TimeZoneSettings::ChangeTimeZoneByDisplayName(param::hstring const& timeZoneDisplayName)
    {
        impl::call_factory<TimeZoneSettings, ITimeZoneSettingsStatics>([&](ITimeZoneSettingsStatics const& f) { return f.ChangeTimeZoneByDisplayName(timeZoneDisplayName); });
    }
    inline auto TimeZoneSettings::AutoUpdateTimeZoneAsync(winrt::Windows::Foundation::TimeSpan const& timeout)
    {
        return impl::call_factory<TimeZoneSettings, ITimeZoneSettingsStatics2>([&](ITimeZoneSettingsStatics2 const& f) { return f.AutoUpdateTimeZoneAsync(timeout); });
    }
    inline auto User::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::System::UserWatcher(*)(IUserStatics const&), User, IUserStatics>([](IUserStatics const& f) { return f.CreateWatcher(); });
    }
    inline auto User::FindAllAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::User>>(*)(IUserStatics const&), User, IUserStatics>([](IUserStatics const& f) { return f.FindAllAsync(); });
    }
    inline auto User::FindAllAsync(winrt::Windows::System::UserType const& type)
    {
        return impl::call_factory<User, IUserStatics>([&](IUserStatics const& f) { return f.FindAllAsync(type); });
    }
    inline auto User::FindAllAsync(winrt::Windows::System::UserType const& type, winrt::Windows::System::UserAuthenticationStatus const& status)
    {
        return impl::call_factory<User, IUserStatics>([&](IUserStatics const& f) { return f.FindAllAsync(type, status); });
    }
    inline auto User::GetFromId(param::hstring const& nonRoamableId)
    {
        return impl::call_factory<User, IUserStatics>([&](IUserStatics const& f) { return f.GetFromId(nonRoamableId); });
    }
    inline auto User::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::System::User(*)(IUserStatics2 const&), User, IUserStatics2>([](IUserStatics2 const& f) { return f.GetDefault(); });
    }
    inline auto UserDeviceAssociation::FindUserFromDeviceId(param::hstring const& deviceId)
    {
        return impl::call_factory<UserDeviceAssociation, IUserDeviceAssociationStatics>([&](IUserDeviceAssociationStatics const& f) { return f.FindUserFromDeviceId(deviceId); });
    }
    inline auto UserDeviceAssociation::UserDeviceAssociationChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> const& handler)
    {
        return impl::call_factory<UserDeviceAssociation, IUserDeviceAssociationStatics>([&](IUserDeviceAssociationStatics const& f) { return f.UserDeviceAssociationChanged(handler); });
    }
    inline UserDeviceAssociation::UserDeviceAssociationChanged_revoker UserDeviceAssociation::UserDeviceAssociationChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> const& handler)
    {
        auto f = get_activation_factory<UserDeviceAssociation, winrt::Windows::System::IUserDeviceAssociationStatics>();
        return { f, f.UserDeviceAssociationChanged(handler) };
    }
    inline auto UserDeviceAssociation::UserDeviceAssociationChanged(winrt::event_token const& token)
    {
        impl::call_factory<UserDeviceAssociation, IUserDeviceAssociationStatics>([&](IUserDeviceAssociationStatics const& f) { return f.UserDeviceAssociationChanged(token); });
    }
    inline UserPicker::UserPicker() :
        UserPicker(impl::call_factory_cast<UserPicker(*)(winrt::Windows::Foundation::IActivationFactory const&), UserPicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<UserPicker>(); }))
    {
    }
    inline auto UserPicker::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IUserPickerStatics const&), UserPicker, IUserPickerStatics>([](IUserPickerStatics const& f) { return f.IsSupported(); });
    }
    template <typename L> DispatcherQueueHandler::DispatcherQueueHandler(L handler) :
        DispatcherQueueHandler(impl::make_delegate<DispatcherQueueHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DispatcherQueueHandler::DispatcherQueueHandler(F* handler) :
        DispatcherQueueHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DispatcherQueueHandler::DispatcherQueueHandler(O* object, M method) :
        DispatcherQueueHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DispatcherQueueHandler::DispatcherQueueHandler(com_ptr<O>&& object, M method) :
        DispatcherQueueHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DispatcherQueueHandler::DispatcherQueueHandler(weak_ref<O>&& object, M method) :
        DispatcherQueueHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DispatcherQueueHandler::operator()() const
    {
        check_hresult((*(impl::abi_t<DispatcherQueueHandler>**)this)->Invoke());
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::IAppActivationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfo3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoWatcherEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppExecutionStateChangeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppMemoryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppMemoryReport2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupBackgroundTaskReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupInfoWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupMemoryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppResourceGroupStateReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerHost> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerHost2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerHostFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistration2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistrationManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistrationManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDateTimeSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueue2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueueController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueueControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueueShutdownStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueueStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IDispatcherQueueTimer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IFolderLauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IKnownUserPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IKnownUserPropertiesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILaunchUriResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherOptions3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherOptions4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherUIOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ILauncherViewOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IMemoryManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IMemoryManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IMemoryManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IMemoryManagerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IProcessLauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IProcessLauncherResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IProcessLauncherStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IProcessMemoryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IProtocolForResultsOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IRemoteLauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IRemoteLauncherStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IShutdownManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IShutdownManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ITimeZoneSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ITimeZoneSettingsStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUser2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserAuthenticationStatusChangeDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserChangedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserDeviceAssociationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserDeviceAssociationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserPickerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::IUserWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppActivationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppDiagnosticInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppDiagnosticInfoWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppExecutionStateChangeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppMemoryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupBackgroundTaskReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupInfoWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupMemoryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppResourceGroupStateReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppUriHandlerHost> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppUriHandlerRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::AppUriHandlerRegistrationManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::DateTimeSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::DispatcherQueue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::DispatcherQueueController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::DispatcherQueueShutdownStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::DispatcherQueueTimer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::FolderLauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::KnownUserProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::LaunchUriResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Launcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::LauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::LauncherUIOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::MemoryManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ProcessLauncher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ProcessLauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ProcessLauncherResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ProcessMemoryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ProtocolForResultsOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteLauncher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteLauncherOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::ShutdownManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::TimeZoneSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::User> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserAuthenticationStatusChangeDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserAuthenticationStatusChangingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserDeviceAssociation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::UserWatcher> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}

WINRT_EXPORT namespace winrt
{
    [[nodiscard]] inline auto resume_foreground(
        Windows::System::DispatcherQueue const& dispatcher,
        Windows::System::DispatcherQueuePriority const priority = Windows::System::DispatcherQueuePriority::Normal) noexcept
    {
        struct awaitable
        {
            awaitable(Windows::System::DispatcherQueue const& dispatcher, Windows::System::DispatcherQueuePriority const priority) noexcept :
                m_dispatcher(dispatcher),
                m_priority(priority)
            {
            }

            bool await_ready() const noexcept
            {
                return false;
            }

            bool await_resume() const noexcept
            {
                return m_queued;
            }

            bool await_suspend(impl::coroutine_handle<> handle)
            {
                return m_dispatcher.TryEnqueue(m_priority, [handle, this]
                    {
                        m_queued = true;
                        handle();
                    });
            }

        private:
            Windows::System::DispatcherQueue const& m_dispatcher;
            Windows::System::DispatcherQueuePriority const m_priority;
            bool m_queued{};
        };

        return awaitable{ dispatcher, priority };
    };

#ifdef WINRT_IMPL_COROUTINES
    inline auto operator co_await(Windows::System::DispatcherQueue const& dispatcher)
    {
        return resume_foreground(dispatcher);
    }
#endif
}
#endif
