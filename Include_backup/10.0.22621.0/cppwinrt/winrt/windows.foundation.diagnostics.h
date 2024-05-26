// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Foundation_Diagnostics_H
#define WINRT_Windows_Foundation_Diagnostics_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Foundation.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Foundation.Diagnostics.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TraceOperationCreation(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, param::hstring const& operationName, uint64_t relatedContext) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->TraceOperationCreation(static_cast<int32_t>(traceLevel), static_cast<int32_t>(source), impl::bind_in(platformId), operationId, *(void**)(&operationName), relatedContext));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TraceOperationCompletion(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, winrt::Windows::Foundation::AsyncStatus const& status) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->TraceOperationCompletion(static_cast<int32_t>(traceLevel), static_cast<int32_t>(source), impl::bind_in(platformId), operationId, static_cast<int32_t>(status)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TraceOperationRelation(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, winrt::Windows::Foundation::Diagnostics::CausalityRelation const& relation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->TraceOperationRelation(static_cast<int32_t>(traceLevel), static_cast<int32_t>(source), impl::bind_in(platformId), operationId, static_cast<int32_t>(relation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TraceSynchronousWorkStart(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, winrt::Windows::Foundation::Diagnostics::CausalitySynchronousWork const& work) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->TraceSynchronousWorkStart(static_cast<int32_t>(traceLevel), static_cast<int32_t>(source), impl::bind_in(platformId), operationId, static_cast<int32_t>(work)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TraceSynchronousWorkCompletion(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::Windows::Foundation::Diagnostics::CausalitySynchronousWork const& work) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->TraceSynchronousWorkCompletion(static_cast<int32_t>(traceLevel), static_cast<int32_t>(source), static_cast<int32_t>(work)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TracingStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::Diagnostics::TracingStatusChangedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->add_TracingStatusChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TracingStatusChanged_revoker consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TracingStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::Diagnostics::TracingStatusChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TracingStatusChanged_revoker>(this, TracingStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IAsyncCausalityTracerStatics<D>::TracingStatusChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics)->remove_TracingStatusChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Foundation_Diagnostics_IErrorDetails<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IErrorDetails)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Foundation_Diagnostics_IErrorDetails<D>::LongDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IErrorDetails)->get_LongDescription(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Foundation_Diagnostics_IErrorDetails<D>::HelpUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IErrorDetails)->get_HelpUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Diagnostics::ErrorDetails>) consume_Windows_Foundation_Diagnostics_IErrorDetailsStatics<D>::CreateFromHResultAsync(int32_t errorCode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IErrorDetailsStatics)->CreateFromHResultAsync(errorCode, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Diagnostics::ErrorDetails>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IErrorReportingSettings<D>::SetErrorOptions(winrt::Windows::Foundation::Diagnostics::ErrorOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IErrorReportingSettings)->SetErrorOptions(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::ErrorOptions) consume_Windows_Foundation_Diagnostics_IErrorReportingSettings<D>::GetErrorOptions() const
    {
        winrt::Windows::Foundation::Diagnostics::ErrorOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IErrorReportingSettings)->GetErrorOptions(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::AddLoggingChannel(winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->AddLoggingChannel(*(void**)(&loggingChannel)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::AddLoggingChannel(winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& maxLevel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->AddLoggingChannelWithLevel(*(void**)(&loggingChannel), static_cast<int32_t>(maxLevel)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::RemoveLoggingChannel(winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->RemoveLoggingChannel(*(void**)(&loggingChannel)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::CloseAndSaveToFileAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->CloseAndSaveToFileAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::LogFileGenerated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::Diagnostics::IFileLoggingSession, winrt::Windows::Foundation::Diagnostics::LogFileGeneratedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->add_LogFileGenerated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::LogFileGenerated_revoker consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::LogFileGenerated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::Diagnostics::IFileLoggingSession, winrt::Windows::Foundation::Diagnostics::LogFileGeneratedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LogFileGenerated_revoker>(this, LogFileGenerated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_IFileLoggingSession<D>::LogFileGenerated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSession)->remove_LogFileGenerated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::FileLoggingSession) consume_Windows_Foundation_Diagnostics_IFileLoggingSessionFactory<D>::Create(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::IFileLoggingSessionFactory)->Create(*(void**)(&name), &result));
        return winrt::Windows::Foundation::Diagnostics::FileLoggingSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Foundation_Diagnostics_ILogFileGeneratedEventArgs<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILogFileGeneratedEventArgs)->get_File(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Foundation_Diagnostics_ILoggingActivity<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivity)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Foundation_Diagnostics_ILoggingActivity<D>::Id() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivity)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingChannel) consume_Windows_Foundation_Diagnostics_ILoggingActivity2<D>::Channel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivity2)->get_Channel(&value));
        return winrt::Windows::Foundation::Diagnostics::LoggingChannel{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingActivity2<D>::StopActivity(param::hstring const& stopEventName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivity2)->StopActivity(*(void**)(&stopEventName)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingActivity2<D>::StopActivity(param::hstring const& stopEventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivity2)->StopActivityWithFields(*(void**)(&stopEventName), *(void**)(&fields)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingActivity2<D>::StopActivity(param::hstring const& stopEventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields, winrt::Windows::Foundation::Diagnostics::LoggingOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivity2)->StopActivityWithFieldsAndOptions(*(void**)(&stopEventName), *(void**)(&fields), *(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingActivity) consume_Windows_Foundation_Diagnostics_ILoggingActivityFactory<D>::CreateLoggingActivity(param::hstring const& activityName, winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel) const
    {
        void* loggingActivity{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivityFactory)->CreateLoggingActivity(*(void**)(&activityName), *(void**)(&loggingChannel), &loggingActivity));
        return winrt::Windows::Foundation::Diagnostics::LoggingActivity{ loggingActivity, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingActivity) consume_Windows_Foundation_Diagnostics_ILoggingActivityFactory<D>::CreateLoggingActivityWithLevel(param::hstring const& activityName, winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) const
    {
        void* loggingActivity{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingActivityFactory)->CreateLoggingActivityWithLevel(*(void**)(&activityName), *(void**)(&loggingChannel), static_cast<int32_t>(level), &loggingActivity));
        return winrt::Windows::Foundation::Diagnostics::LoggingActivity{ loggingActivity, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::Enabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->get_Enabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingLevel) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::Level() const
    {
        winrt::Windows::Foundation::Diagnostics::LoggingLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->get_Level(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LogMessage(param::hstring const& eventString) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->LogMessage(*(void**)(&eventString)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LogMessage(param::hstring const& eventString, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->LogMessageWithLevel(*(void**)(&eventString), static_cast<int32_t>(level)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LogValuePair(param::hstring const& value1, int32_t value2) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->LogValuePair(*(void**)(&value1), value2));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LogValuePair(param::hstring const& value1, int32_t value2, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->LogValuePairWithLevel(*(void**)(&value1), value2, static_cast<int32_t>(level)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LoggingEnabled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::Diagnostics::ILoggingChannel, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->add_LoggingEnabled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LoggingEnabled_revoker consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LoggingEnabled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::Diagnostics::ILoggingChannel, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, LoggingEnabled_revoker>(this, LoggingEnabled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingChannel<D>::LoggingEnabled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel)->remove_LoggingEnabled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Foundation_Diagnostics_ILoggingChannel2<D>::Id() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannel2)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingChannel) consume_Windows_Foundation_Diagnostics_ILoggingChannelFactory<D>::Create(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory)->Create(*(void**)(&name), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingChannel{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingChannel) consume_Windows_Foundation_Diagnostics_ILoggingChannelFactory2<D>::CreateWithOptions(param::hstring const& name, winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory2)->CreateWithOptions(*(void**)(&name), *(void**)(&options), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingChannel{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingChannel) consume_Windows_Foundation_Diagnostics_ILoggingChannelFactory2<D>::CreateWithOptionsAndId(param::hstring const& name, winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions const& options, winrt::guid const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory2)->CreateWithOptionsAndId(*(void**)(&name), *(void**)(&options), impl::bind_in(id), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingChannel{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Foundation_Diagnostics_ILoggingChannelOptions<D>::Group() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptions)->get_Group(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingChannelOptions<D>::Group(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptions)->put_Group(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions) consume_Windows_Foundation_Diagnostics_ILoggingChannelOptionsFactory<D>::Create(winrt::guid const& group) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptionsFactory)->Create(impl::bind_in(group), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::BeginStruct(param::hstring const& name) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->BeginStruct(*(void**)(&name)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::BeginStruct(param::hstring const& name, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->BeginStructWithTags(*(void**)(&name), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::EndStruct() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->EndStruct());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddEmpty(param::hstring const& name) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddEmpty(*(void**)(&name)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddEmpty(param::hstring const& name, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddEmptyWithFormat(*(void**)(&name), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddEmpty(param::hstring const& name, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddEmptyWithFormatAndTags(*(void**)(&name), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt8(param::hstring const& name, uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt8(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt8(param::hstring const& name, uint8_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt8WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt8(param::hstring const& name, uint8_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt8WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt8Array(param::hstring const& name, array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt8Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt8Array(param::hstring const& name, array_view<uint8_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt8ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt8Array(param::hstring const& name, array_view<uint8_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt8ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt16(param::hstring const& name, int16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt16(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt16(param::hstring const& name, int16_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt16WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt16(param::hstring const& name, int16_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt16WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt16Array(param::hstring const& name, array_view<int16_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt16Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt16Array(param::hstring const& name, array_view<int16_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt16ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt16Array(param::hstring const& name, array_view<int16_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt16ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt16(param::hstring const& name, uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt16(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt16(param::hstring const& name, uint16_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt16WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt16(param::hstring const& name, uint16_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt16WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt16Array(param::hstring const& name, array_view<uint16_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt16Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt16Array(param::hstring const& name, array_view<uint16_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt16ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt16Array(param::hstring const& name, array_view<uint16_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt16ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt32(param::hstring const& name, int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt32(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt32(param::hstring const& name, int32_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt32WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt32(param::hstring const& name, int32_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt32WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt32Array(param::hstring const& name, array_view<int32_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt32Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt32Array(param::hstring const& name, array_view<int32_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt32ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt32Array(param::hstring const& name, array_view<int32_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt32ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt32(param::hstring const& name, uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt32(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt32(param::hstring const& name, uint32_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt32WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt32(param::hstring const& name, uint32_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt32WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt32Array(param::hstring const& name, array_view<uint32_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt32Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt32Array(param::hstring const& name, array_view<uint32_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt32ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt32Array(param::hstring const& name, array_view<uint32_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt32ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt64(param::hstring const& name, int64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt64(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt64(param::hstring const& name, int64_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt64WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt64(param::hstring const& name, int64_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt64WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt64Array(param::hstring const& name, array_view<int64_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt64Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt64Array(param::hstring const& name, array_view<int64_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt64ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddInt64Array(param::hstring const& name, array_view<int64_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddInt64ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt64(param::hstring const& name, uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt64(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt64(param::hstring const& name, uint64_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt64WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt64(param::hstring const& name, uint64_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt64WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt64Array(param::hstring const& name, array_view<uint64_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt64Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt64Array(param::hstring const& name, array_view<uint64_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt64ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddUInt64Array(param::hstring const& name, array_view<uint64_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddUInt64ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSingle(param::hstring const& name, float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSingle(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSingle(param::hstring const& name, float value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSingleWithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSingle(param::hstring const& name, float value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSingleWithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSingleArray(param::hstring const& name, array_view<float const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSingleArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSingleArray(param::hstring const& name, array_view<float const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSingleArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSingleArray(param::hstring const& name, array_view<float const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSingleArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDouble(param::hstring const& name, double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDouble(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDouble(param::hstring const& name, double value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDoubleWithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDouble(param::hstring const& name, double value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDoubleWithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDoubleArray(param::hstring const& name, array_view<double const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDoubleArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDoubleArray(param::hstring const& name, array_view<double const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDoubleArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDoubleArray(param::hstring const& name, array_view<double const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDoubleArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddChar16(param::hstring const& name, char16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddChar16(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddChar16(param::hstring const& name, char16_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddChar16WithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddChar16(param::hstring const& name, char16_t value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddChar16WithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddChar16Array(param::hstring const& name, array_view<char16_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddChar16Array(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddChar16Array(param::hstring const& name, array_view<char16_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddChar16ArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddChar16Array(param::hstring const& name, array_view<char16_t const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddChar16ArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddBoolean(param::hstring const& name, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddBoolean(*(void**)(&name), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddBoolean(param::hstring const& name, bool value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddBooleanWithFormat(*(void**)(&name), value, static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddBoolean(param::hstring const& name, bool value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddBooleanWithFormatAndTags(*(void**)(&name), value, static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddBooleanArray(param::hstring const& name, array_view<bool const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddBooleanArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddBooleanArray(param::hstring const& name, array_view<bool const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddBooleanArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddBooleanArray(param::hstring const& name, array_view<bool const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddBooleanArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddString(param::hstring const& name, param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddString(*(void**)(&name), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddString(param::hstring const& name, param::hstring const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddStringWithFormat(*(void**)(&name), *(void**)(&value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddString(param::hstring const& name, param::hstring const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddStringWithFormatAndTags(*(void**)(&name), *(void**)(&value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddStringArray(param::hstring const& name, array_view<hstring const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddStringArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddStringArray(param::hstring const& name, array_view<hstring const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddStringArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddStringArray(param::hstring const& name, array_view<hstring const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddStringArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddGuid(param::hstring const& name, winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddGuid(*(void**)(&name), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddGuid(param::hstring const& name, winrt::guid const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddGuidWithFormat(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddGuid(param::hstring const& name, winrt::guid const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddGuidWithFormatAndTags(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddGuidArray(param::hstring const& name, array_view<winrt::guid const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddGuidArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddGuidArray(param::hstring const& name, array_view<winrt::guid const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddGuidArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddGuidArray(param::hstring const& name, array_view<winrt::guid const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddGuidArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDateTime(param::hstring const& name, winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDateTime(*(void**)(&name), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDateTime(param::hstring const& name, winrt::Windows::Foundation::DateTime const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDateTimeWithFormat(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDateTime(param::hstring const& name, winrt::Windows::Foundation::DateTime const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDateTimeWithFormatAndTags(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDateTimeArray(param::hstring const& name, array_view<winrt::Windows::Foundation::DateTime const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDateTimeArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDateTimeArray(param::hstring const& name, array_view<winrt::Windows::Foundation::DateTime const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDateTimeArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddDateTimeArray(param::hstring const& name, array_view<winrt::Windows::Foundation::DateTime const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddDateTimeArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddTimeSpan(param::hstring const& name, winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddTimeSpan(*(void**)(&name), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddTimeSpan(param::hstring const& name, winrt::Windows::Foundation::TimeSpan const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddTimeSpanWithFormat(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddTimeSpan(param::hstring const& name, winrt::Windows::Foundation::TimeSpan const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddTimeSpanWithFormatAndTags(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddTimeSpanArray(param::hstring const& name, array_view<winrt::Windows::Foundation::TimeSpan const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddTimeSpanArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddTimeSpanArray(param::hstring const& name, array_view<winrt::Windows::Foundation::TimeSpan const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddTimeSpanArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddTimeSpanArray(param::hstring const& name, array_view<winrt::Windows::Foundation::TimeSpan const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddTimeSpanArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddPoint(param::hstring const& name, winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddPoint(*(void**)(&name), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddPoint(param::hstring const& name, winrt::Windows::Foundation::Point const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddPointWithFormat(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddPoint(param::hstring const& name, winrt::Windows::Foundation::Point const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddPointWithFormatAndTags(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddPointArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Point const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddPointArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddPointArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Point const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddPointArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddPointArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Point const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddPointArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSize(param::hstring const& name, winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSize(*(void**)(&name), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSize(param::hstring const& name, winrt::Windows::Foundation::Size const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSizeWithFormat(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSize(param::hstring const& name, winrt::Windows::Foundation::Size const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSizeWithFormatAndTags(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSizeArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Size const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSizeArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSizeArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Size const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSizeArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddSizeArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Size const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddSizeArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddRect(param::hstring const& name, winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddRect(*(void**)(&name), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddRect(param::hstring const& name, winrt::Windows::Foundation::Rect const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddRectWithFormat(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddRect(param::hstring const& name, winrt::Windows::Foundation::Rect const& value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddRectWithFormatAndTags(*(void**)(&name), impl::bind_in(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddRectArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Rect const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddRectArray(*(void**)(&name), value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddRectArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Rect const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddRectArrayWithFormat(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingFields<D>::AddRectArray(param::hstring const& name, array_view<winrt::Windows::Foundation::Rect const> value, winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const& format, int32_t tags) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingFields)->AddRectArrayWithFormatAndTags(*(void**)(&name), value.size(), get_abi(value), static_cast<int32_t>(format), tags));
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Keywords() const
    {
        int64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->get_Keywords(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Keywords(int64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->put_Keywords(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Tags() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->get_Tags(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Tags(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->put_Tags(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int16_t) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Task() const
    {
        int16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->get_Task(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Task(int16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->put_Task(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingOpcode) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Opcode() const
    {
        winrt::Windows::Foundation::Diagnostics::LoggingOpcode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->get_Opcode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::Opcode(winrt::Windows::Foundation::Diagnostics::LoggingOpcode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->put_Opcode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::ActivityId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->get_ActivityId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::ActivityId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->put_ActivityId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::RelatedActivityId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->get_RelatedActivityId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingOptions<D>::RelatedActivityId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptions)->put_RelatedActivityId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingOptions) consume_Windows_Foundation_Diagnostics_ILoggingOptionsFactory<D>::CreateWithKeywords(int64_t keywords) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingOptionsFactory)->CreateWithKeywords(keywords, &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingOptions{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Foundation_Diagnostics_ILoggingSession<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingSession)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Foundation_Diagnostics_ILoggingSession<D>::SaveToFileAsync(winrt::Windows::Storage::IStorageFolder const& folder, param::hstring const& fileName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingSession)->SaveToFileAsync(*(void**)(&folder), *(void**)(&fileName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingSession<D>::AddLoggingChannel(winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingSession)->AddLoggingChannel(*(void**)(&loggingChannel)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingSession<D>::AddLoggingChannel(winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& maxLevel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingSession)->AddLoggingChannelWithLevel(*(void**)(&loggingChannel), static_cast<int32_t>(maxLevel)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingSession<D>::RemoveLoggingChannel(winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingSession)->RemoveLoggingChannel(*(void**)(&loggingChannel)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingSession) consume_Windows_Foundation_Diagnostics_ILoggingSessionFactory<D>::Create(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingSessionFactory)->Create(*(void**)(&name), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::IsEnabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->IsEnabled(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::IsEnabled(winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->IsEnabledWithLevel(static_cast<int32_t>(level), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::IsEnabled(winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level, int64_t keywords) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->IsEnabledWithLevelAndKeywords(static_cast<int32_t>(level), keywords, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::LogEvent(param::hstring const& eventName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->LogEvent(*(void**)(&eventName)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::LogEvent(param::hstring const& eventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->LogEventWithFields(*(void**)(&eventName), *(void**)(&fields)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::LogEvent(param::hstring const& eventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->LogEventWithFieldsAndLevel(*(void**)(&eventName), *(void**)(&fields), static_cast<int32_t>(level)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::LogEvent(param::hstring const& eventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level, winrt::Windows::Foundation::Diagnostics::LoggingOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->LogEventWithFieldsAndOptions(*(void**)(&eventName), *(void**)(&fields), static_cast<int32_t>(level), *(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingActivity) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::StartActivity(param::hstring const& startEventName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->StartActivity(*(void**)(&startEventName), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingActivity{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingActivity) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::StartActivity(param::hstring const& startEventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->StartActivityWithFields(*(void**)(&startEventName), *(void**)(&fields), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingActivity{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingActivity) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::StartActivity(param::hstring const& startEventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->StartActivityWithFieldsAndLevel(*(void**)(&startEventName), *(void**)(&fields), static_cast<int32_t>(level), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingActivity{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::LoggingActivity) consume_Windows_Foundation_Diagnostics_ILoggingTarget<D>::StartActivity(param::hstring const& startEventName, winrt::Windows::Foundation::Diagnostics::LoggingFields const& fields, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level, winrt::Windows::Foundation::Diagnostics::LoggingOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ILoggingTarget)->StartActivityWithFieldsAndOptions(*(void**)(&startEventName), *(void**)(&fields), static_cast<int32_t>(level), *(void**)(&options), &result));
        return winrt::Windows::Foundation::Diagnostics::LoggingActivity{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Foundation_Diagnostics_ITracingStatusChangedEventArgs<D>::Enabled() const
    {
        bool enabled{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ITracingStatusChangedEventArgs)->get_Enabled(&enabled));
        return enabled;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel) consume_Windows_Foundation_Diagnostics_ITracingStatusChangedEventArgs<D>::TraceLevel() const
    {
        winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Foundation::Diagnostics::ITracingStatusChangedEventArgs)->get_TraceLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics> : produce_base<D, winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics>
    {
        int32_t __stdcall TraceOperationCreation(int32_t traceLevel, int32_t source, winrt::guid platformId, uint64_t operationId, void* operationName, uint64_t relatedContext) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TraceOperationCreation(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const*>(&traceLevel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySource const*>(&source), *reinterpret_cast<winrt::guid const*>(&platformId), operationId, *reinterpret_cast<hstring const*>(&operationName), relatedContext);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TraceOperationCompletion(int32_t traceLevel, int32_t source, winrt::guid platformId, uint64_t operationId, int32_t status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TraceOperationCompletion(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const*>(&traceLevel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySource const*>(&source), *reinterpret_cast<winrt::guid const*>(&platformId), operationId, *reinterpret_cast<winrt::Windows::Foundation::AsyncStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TraceOperationRelation(int32_t traceLevel, int32_t source, winrt::guid platformId, uint64_t operationId, int32_t relation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TraceOperationRelation(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const*>(&traceLevel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySource const*>(&source), *reinterpret_cast<winrt::guid const*>(&platformId), operationId, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalityRelation const*>(&relation));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TraceSynchronousWorkStart(int32_t traceLevel, int32_t source, winrt::guid platformId, uint64_t operationId, int32_t work) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TraceSynchronousWorkStart(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const*>(&traceLevel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySource const*>(&source), *reinterpret_cast<winrt::guid const*>(&platformId), operationId, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySynchronousWork const*>(&work));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TraceSynchronousWorkCompletion(int32_t traceLevel, int32_t source, int32_t work) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TraceSynchronousWorkCompletion(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const*>(&traceLevel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySource const*>(&source), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::CausalitySynchronousWork const*>(&work));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_TracingStatusChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().TracingStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::Diagnostics::TracingStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TracingStatusChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TracingStatusChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::IErrorDetails> : produce_base<D, winrt::Windows::Foundation::Diagnostics::IErrorDetails>
    {
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LongDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LongDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HelpUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().HelpUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::IErrorDetailsStatics> : produce_base<D, winrt::Windows::Foundation::Diagnostics::IErrorDetailsStatics>
    {
        int32_t __stdcall CreateFromHResultAsync(int32_t errorCode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Diagnostics::ErrorDetails>>(this->shim().CreateFromHResultAsync(errorCode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::IErrorReportingSettings> : produce_base<D, winrt::Windows::Foundation::Diagnostics::IErrorReportingSettings>
    {
        int32_t __stdcall SetErrorOptions(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetErrorOptions(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ErrorOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetErrorOptions(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Diagnostics::ErrorOptions>(this->shim().GetErrorOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::IFileLoggingSession> : produce_base<D, winrt::Windows::Foundation::Diagnostics::IFileLoggingSession>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddLoggingChannel(void* loggingChannel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddLoggingChannel(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddLoggingChannelWithLevel(void* loggingChannel, int32_t maxLevel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddLoggingChannel(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&maxLevel));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveLoggingChannel(void* loggingChannel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveLoggingChannel(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CloseAndSaveToFileAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CloseAndSaveToFileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_LogFileGenerated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LogFileGenerated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::Diagnostics::IFileLoggingSession, winrt::Windows::Foundation::Diagnostics::LogFileGeneratedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LogFileGenerated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogFileGenerated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::IFileLoggingSessionFactory> : produce_base<D, winrt::Windows::Foundation::Diagnostics::IFileLoggingSessionFactory>
    {
        int32_t __stdcall Create(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::FileLoggingSession>(this->shim().Create(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILogFileGeneratedEventArgs> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILogFileGeneratedEventArgs>
    {
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingActivity> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingActivity>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingActivity2> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingActivity2>
    {
        int32_t __stdcall get_Channel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingChannel>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopActivity(void* stopEventName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopActivity(*reinterpret_cast<hstring const*>(&stopEventName));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopActivityWithFields(void* stopEventName, void* fields) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopActivity(*reinterpret_cast<hstring const*>(&stopEventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopActivityWithFieldsAndOptions(void* stopEventName, void* fields, void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopActivity(*reinterpret_cast<hstring const*>(&stopEventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingActivityFactory> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingActivityFactory>
    {
        int32_t __stdcall CreateLoggingActivity(void* activityName, void* loggingChannel, void** loggingActivity) noexcept final try
        {
            clear_abi(loggingActivity);
            typename D::abi_guard guard(this->shim());
            *loggingActivity = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingActivity>(this->shim().CreateLoggingActivity(*reinterpret_cast<hstring const*>(&activityName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateLoggingActivityWithLevel(void* activityName, void* loggingChannel, int32_t level, void** loggingActivity) noexcept final try
        {
            clear_abi(loggingActivity);
            typename D::abi_guard guard(this->shim());
            *loggingActivity = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingActivity>(this->shim().CreateLoggingActivityWithLevel(*reinterpret_cast<hstring const*>(&activityName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannel> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannel>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Enabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Level(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingLevel>(this->shim().Level());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogMessage(void* eventString) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogMessage(*reinterpret_cast<hstring const*>(&eventString));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogMessageWithLevel(void* eventString, int32_t level) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogMessage(*reinterpret_cast<hstring const*>(&eventString), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogValuePair(void* value1, int32_t value2) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogValuePair(*reinterpret_cast<hstring const*>(&value1), value2);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogValuePairWithLevel(void* value1, int32_t value2, int32_t level) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogValuePair(*reinterpret_cast<hstring const*>(&value1), value2, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_LoggingEnabled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LoggingEnabled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::Diagnostics::ILoggingChannel, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LoggingEnabled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoggingEnabled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannel2> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannel2>
    {
        int32_t __stdcall get_Id(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory>
    {
        int32_t __stdcall Create(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingChannel>(this->shim().Create(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory2> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory2>
    {
        int32_t __stdcall CreateWithOptions(void* name, void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingChannel>(this->shim().CreateWithOptions(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithOptionsAndId(void* name, void* options, winrt::guid id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingChannel>(this->shim().CreateWithOptionsAndId(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions const*>(&options), *reinterpret_cast<winrt::guid const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptions> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptions>
    {
        int32_t __stdcall get_Group(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Group(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Group(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptionsFactory> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptionsFactory>
    {
        int32_t __stdcall Create(winrt::guid group, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions>(this->shim().Create(*reinterpret_cast<winrt::guid const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingFields> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingFields>
    {
        int32_t __stdcall Clear() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BeginStruct(void* name) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeginStruct(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BeginStructWithTags(void* name, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeginStruct(*reinterpret_cast<hstring const*>(&name), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EndStruct() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndStruct();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddEmpty(void* name) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddEmpty(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddEmptyWithFormat(void* name, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddEmpty(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddEmptyWithFormatAndTags(void* name, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddEmpty(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt8(void* name, uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt8(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt8WithFormat(void* name, uint8_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt8(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt8WithFormatAndTags(void* name, uint8_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt8(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt8Array(void* name, uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt8Array(*reinterpret_cast<hstring const*>(&name), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt8ArrayWithFormat(void* name, uint32_t __valueSize, uint8_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt8Array(*reinterpret_cast<hstring const*>(&name), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt8ArrayWithFormatAndTags(void* name, uint32_t __valueSize, uint8_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt8Array(*reinterpret_cast<hstring const*>(&name), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt16(void* name, int16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt16(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt16WithFormat(void* name, int16_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt16(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt16WithFormatAndTags(void* name, int16_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt16(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt16Array(void* name, uint32_t __valueSize, int16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt16Array(*reinterpret_cast<hstring const*>(&name), array_view<int16_t const>(reinterpret_cast<int16_t const *>(value), reinterpret_cast<int16_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt16ArrayWithFormat(void* name, uint32_t __valueSize, int16_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt16Array(*reinterpret_cast<hstring const*>(&name), array_view<int16_t const>(reinterpret_cast<int16_t const *>(value), reinterpret_cast<int16_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt16ArrayWithFormatAndTags(void* name, uint32_t __valueSize, int16_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt16Array(*reinterpret_cast<hstring const*>(&name), array_view<int16_t const>(reinterpret_cast<int16_t const *>(value), reinterpret_cast<int16_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt16(void* name, uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt16(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt16WithFormat(void* name, uint16_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt16(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt16WithFormatAndTags(void* name, uint16_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt16(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt16Array(void* name, uint32_t __valueSize, uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt16Array(*reinterpret_cast<hstring const*>(&name), array_view<uint16_t const>(reinterpret_cast<uint16_t const *>(value), reinterpret_cast<uint16_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt16ArrayWithFormat(void* name, uint32_t __valueSize, uint16_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt16Array(*reinterpret_cast<hstring const*>(&name), array_view<uint16_t const>(reinterpret_cast<uint16_t const *>(value), reinterpret_cast<uint16_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt16ArrayWithFormatAndTags(void* name, uint32_t __valueSize, uint16_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt16Array(*reinterpret_cast<hstring const*>(&name), array_view<uint16_t const>(reinterpret_cast<uint16_t const *>(value), reinterpret_cast<uint16_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32(void* name, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32WithFormat(void* name, int32_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32WithFormatAndTags(void* name, int32_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32Array(void* name, uint32_t __valueSize, int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32Array(*reinterpret_cast<hstring const*>(&name), array_view<int32_t const>(reinterpret_cast<int32_t const *>(value), reinterpret_cast<int32_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32ArrayWithFormat(void* name, uint32_t __valueSize, int32_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32Array(*reinterpret_cast<hstring const*>(&name), array_view<int32_t const>(reinterpret_cast<int32_t const *>(value), reinterpret_cast<int32_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32ArrayWithFormatAndTags(void* name, uint32_t __valueSize, int32_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32Array(*reinterpret_cast<hstring const*>(&name), array_view<int32_t const>(reinterpret_cast<int32_t const *>(value), reinterpret_cast<int32_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt32(void* name, uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt32(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt32WithFormat(void* name, uint32_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt32(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt32WithFormatAndTags(void* name, uint32_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt32(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt32Array(void* name, uint32_t __valueSize, uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt32Array(*reinterpret_cast<hstring const*>(&name), array_view<uint32_t const>(reinterpret_cast<uint32_t const *>(value), reinterpret_cast<uint32_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt32ArrayWithFormat(void* name, uint32_t __valueSize, uint32_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt32Array(*reinterpret_cast<hstring const*>(&name), array_view<uint32_t const>(reinterpret_cast<uint32_t const *>(value), reinterpret_cast<uint32_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt32ArrayWithFormatAndTags(void* name, uint32_t __valueSize, uint32_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt32Array(*reinterpret_cast<hstring const*>(&name), array_view<uint32_t const>(reinterpret_cast<uint32_t const *>(value), reinterpret_cast<uint32_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt64(void* name, int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt64(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt64WithFormat(void* name, int64_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt64(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt64WithFormatAndTags(void* name, int64_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt64(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt64Array(void* name, uint32_t __valueSize, int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt64Array(*reinterpret_cast<hstring const*>(&name), array_view<int64_t const>(reinterpret_cast<int64_t const *>(value), reinterpret_cast<int64_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt64ArrayWithFormat(void* name, uint32_t __valueSize, int64_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt64Array(*reinterpret_cast<hstring const*>(&name), array_view<int64_t const>(reinterpret_cast<int64_t const *>(value), reinterpret_cast<int64_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt64ArrayWithFormatAndTags(void* name, uint32_t __valueSize, int64_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt64Array(*reinterpret_cast<hstring const*>(&name), array_view<int64_t const>(reinterpret_cast<int64_t const *>(value), reinterpret_cast<int64_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt64(void* name, uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt64(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt64WithFormat(void* name, uint64_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt64(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt64WithFormatAndTags(void* name, uint64_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt64(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt64Array(void* name, uint32_t __valueSize, uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt64Array(*reinterpret_cast<hstring const*>(&name), array_view<uint64_t const>(reinterpret_cast<uint64_t const *>(value), reinterpret_cast<uint64_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt64ArrayWithFormat(void* name, uint32_t __valueSize, uint64_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt64Array(*reinterpret_cast<hstring const*>(&name), array_view<uint64_t const>(reinterpret_cast<uint64_t const *>(value), reinterpret_cast<uint64_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddUInt64ArrayWithFormatAndTags(void* name, uint32_t __valueSize, uint64_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddUInt64Array(*reinterpret_cast<hstring const*>(&name), array_view<uint64_t const>(reinterpret_cast<uint64_t const *>(value), reinterpret_cast<uint64_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSingle(void* name, float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSingle(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSingleWithFormat(void* name, float value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSingle(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSingleWithFormatAndTags(void* name, float value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSingle(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSingleArray(void* name, uint32_t __valueSize, float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSingleArray(*reinterpret_cast<hstring const*>(&name), array_view<float const>(reinterpret_cast<float const *>(value), reinterpret_cast<float const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSingleArrayWithFormat(void* name, uint32_t __valueSize, float* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSingleArray(*reinterpret_cast<hstring const*>(&name), array_view<float const>(reinterpret_cast<float const *>(value), reinterpret_cast<float const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSingleArrayWithFormatAndTags(void* name, uint32_t __valueSize, float* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSingleArray(*reinterpret_cast<hstring const*>(&name), array_view<float const>(reinterpret_cast<float const *>(value), reinterpret_cast<float const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDouble(void* name, double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDouble(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDoubleWithFormat(void* name, double value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDouble(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDoubleWithFormatAndTags(void* name, double value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDouble(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDoubleArray(void* name, uint32_t __valueSize, double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDoubleArray(*reinterpret_cast<hstring const*>(&name), array_view<double const>(reinterpret_cast<double const *>(value), reinterpret_cast<double const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDoubleArrayWithFormat(void* name, uint32_t __valueSize, double* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDoubleArray(*reinterpret_cast<hstring const*>(&name), array_view<double const>(reinterpret_cast<double const *>(value), reinterpret_cast<double const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDoubleArrayWithFormatAndTags(void* name, uint32_t __valueSize, double* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDoubleArray(*reinterpret_cast<hstring const*>(&name), array_view<double const>(reinterpret_cast<double const *>(value), reinterpret_cast<double const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddChar16(void* name, char16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddChar16(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddChar16WithFormat(void* name, char16_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddChar16(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddChar16WithFormatAndTags(void* name, char16_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddChar16(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddChar16Array(void* name, uint32_t __valueSize, char16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddChar16Array(*reinterpret_cast<hstring const*>(&name), array_view<char16_t const>(reinterpret_cast<char16_t const *>(value), reinterpret_cast<char16_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddChar16ArrayWithFormat(void* name, uint32_t __valueSize, char16_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddChar16Array(*reinterpret_cast<hstring const*>(&name), array_view<char16_t const>(reinterpret_cast<char16_t const *>(value), reinterpret_cast<char16_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddChar16ArrayWithFormatAndTags(void* name, uint32_t __valueSize, char16_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddChar16Array(*reinterpret_cast<hstring const*>(&name), array_view<char16_t const>(reinterpret_cast<char16_t const *>(value), reinterpret_cast<char16_t const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddBoolean(void* name, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddBoolean(*reinterpret_cast<hstring const*>(&name), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddBooleanWithFormat(void* name, bool value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddBoolean(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddBooleanWithFormatAndTags(void* name, bool value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddBoolean(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddBooleanArray(void* name, uint32_t __valueSize, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddBooleanArray(*reinterpret_cast<hstring const*>(&name), array_view<bool const>(reinterpret_cast<bool const *>(value), reinterpret_cast<bool const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddBooleanArrayWithFormat(void* name, uint32_t __valueSize, bool* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddBooleanArray(*reinterpret_cast<hstring const*>(&name), array_view<bool const>(reinterpret_cast<bool const *>(value), reinterpret_cast<bool const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddBooleanArrayWithFormatAndTags(void* name, uint32_t __valueSize, bool* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddBooleanArray(*reinterpret_cast<hstring const*>(&name), array_view<bool const>(reinterpret_cast<bool const *>(value), reinterpret_cast<bool const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddString(void* name, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddString(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStringWithFormat(void* name, void* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddString(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStringWithFormatAndTags(void* name, void* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddString(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStringArray(void* name, uint32_t __valueSize, void** value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStringArray(*reinterpret_cast<hstring const*>(&name), array_view<hstring const>(reinterpret_cast<hstring const *>(value), reinterpret_cast<hstring const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStringArrayWithFormat(void* name, uint32_t __valueSize, void** value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStringArray(*reinterpret_cast<hstring const*>(&name), array_view<hstring const>(reinterpret_cast<hstring const *>(value), reinterpret_cast<hstring const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStringArrayWithFormatAndTags(void* name, uint32_t __valueSize, void** value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStringArray(*reinterpret_cast<hstring const*>(&name), array_view<hstring const>(reinterpret_cast<hstring const *>(value), reinterpret_cast<hstring const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddGuid(void* name, winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddGuid(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddGuidWithFormat(void* name, winrt::guid value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddGuid(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::guid const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddGuidWithFormatAndTags(void* name, winrt::guid value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddGuid(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::guid const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddGuidArray(void* name, uint32_t __valueSize, winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddGuidArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::guid const>(reinterpret_cast<winrt::guid const *>(value), reinterpret_cast<winrt::guid const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddGuidArrayWithFormat(void* name, uint32_t __valueSize, winrt::guid* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddGuidArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::guid const>(reinterpret_cast<winrt::guid const *>(value), reinterpret_cast<winrt::guid const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddGuidArrayWithFormatAndTags(void* name, uint32_t __valueSize, winrt::guid* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddGuidArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::guid const>(reinterpret_cast<winrt::guid const *>(value), reinterpret_cast<winrt::guid const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDateTime(void* name, int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDateTime(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDateTimeWithFormat(void* name, int64_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDateTime(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDateTimeWithFormatAndTags(void* name, int64_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDateTime(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDateTimeArray(void* name, uint32_t __valueSize, int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDateTimeArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::DateTime const>(reinterpret_cast<winrt::Windows::Foundation::DateTime const *>(value), reinterpret_cast<winrt::Windows::Foundation::DateTime const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDateTimeArrayWithFormat(void* name, uint32_t __valueSize, int64_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDateTimeArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::DateTime const>(reinterpret_cast<winrt::Windows::Foundation::DateTime const *>(value), reinterpret_cast<winrt::Windows::Foundation::DateTime const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDateTimeArrayWithFormatAndTags(void* name, uint32_t __valueSize, int64_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDateTimeArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::DateTime const>(reinterpret_cast<winrt::Windows::Foundation::DateTime const *>(value), reinterpret_cast<winrt::Windows::Foundation::DateTime const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddTimeSpan(void* name, int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddTimeSpan(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddTimeSpanWithFormat(void* name, int64_t value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddTimeSpan(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddTimeSpanWithFormatAndTags(void* name, int64_t value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddTimeSpan(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddTimeSpanArray(void* name, uint32_t __valueSize, int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddTimeSpanArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::TimeSpan const>(reinterpret_cast<winrt::Windows::Foundation::TimeSpan const *>(value), reinterpret_cast<winrt::Windows::Foundation::TimeSpan const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddTimeSpanArrayWithFormat(void* name, uint32_t __valueSize, int64_t* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddTimeSpanArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::TimeSpan const>(reinterpret_cast<winrt::Windows::Foundation::TimeSpan const *>(value), reinterpret_cast<winrt::Windows::Foundation::TimeSpan const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddTimeSpanArrayWithFormatAndTags(void* name, uint32_t __valueSize, int64_t* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddTimeSpanArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::TimeSpan const>(reinterpret_cast<winrt::Windows::Foundation::TimeSpan const *>(value), reinterpret_cast<winrt::Windows::Foundation::TimeSpan const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPoint(void* name, winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPoint(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPointWithFormat(void* name, winrt::Windows::Foundation::Point value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPoint(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPointWithFormatAndTags(void* name, winrt::Windows::Foundation::Point value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPoint(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPointArray(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Point* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPointArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Point const>(reinterpret_cast<winrt::Windows::Foundation::Point const *>(value), reinterpret_cast<winrt::Windows::Foundation::Point const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPointArrayWithFormat(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Point* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPointArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Point const>(reinterpret_cast<winrt::Windows::Foundation::Point const *>(value), reinterpret_cast<winrt::Windows::Foundation::Point const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPointArrayWithFormatAndTags(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Point* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPointArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Point const>(reinterpret_cast<winrt::Windows::Foundation::Point const *>(value), reinterpret_cast<winrt::Windows::Foundation::Point const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSize(void* name, winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSize(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSizeWithFormat(void* name, winrt::Windows::Foundation::Size value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSize(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSizeWithFormatAndTags(void* name, winrt::Windows::Foundation::Size value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSize(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSizeArray(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Size* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSizeArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Size const>(reinterpret_cast<winrt::Windows::Foundation::Size const *>(value), reinterpret_cast<winrt::Windows::Foundation::Size const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSizeArrayWithFormat(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Size* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSizeArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Size const>(reinterpret_cast<winrt::Windows::Foundation::Size const *>(value), reinterpret_cast<winrt::Windows::Foundation::Size const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSizeArrayWithFormatAndTags(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Size* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSizeArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Size const>(reinterpret_cast<winrt::Windows::Foundation::Size const *>(value), reinterpret_cast<winrt::Windows::Foundation::Size const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddRect(void* name, winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddRect(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddRectWithFormat(void* name, winrt::Windows::Foundation::Rect value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddRect(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddRectWithFormatAndTags(void* name, winrt::Windows::Foundation::Rect value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddRect(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddRectArray(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddRectArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Rect const>(reinterpret_cast<winrt::Windows::Foundation::Rect const *>(value), reinterpret_cast<winrt::Windows::Foundation::Rect const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddRectArrayWithFormat(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Rect* value, int32_t format) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddRectArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Rect const>(reinterpret_cast<winrt::Windows::Foundation::Rect const *>(value), reinterpret_cast<winrt::Windows::Foundation::Rect const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddRectArrayWithFormatAndTags(void* name, uint32_t __valueSize, winrt::Windows::Foundation::Rect* value, int32_t format, int32_t tags) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddRectArray(*reinterpret_cast<hstring const*>(&name), array_view<winrt::Windows::Foundation::Rect const>(reinterpret_cast<winrt::Windows::Foundation::Rect const *>(value), reinterpret_cast<winrt::Windows::Foundation::Rect const *>(value) + __valueSize), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFieldFormat const*>(&format), tags);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingOptions> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingOptions>
    {
        int32_t __stdcall get_Keywords(int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int64_t>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Keywords(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Keywords(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tags(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Tags());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Tags(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tags(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Task(int16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int16_t>(this->shim().Task());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Task(int16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Task(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Opcode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingOpcode>(this->shim().Opcode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Opcode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opcode(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingOpcode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActivityId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ActivityId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ActivityId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelatedActivityId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().RelatedActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelatedActivityId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelatedActivityId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingOptionsFactory> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingOptionsFactory>
    {
        int32_t __stdcall CreateWithKeywords(int64_t keywords, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingOptions>(this->shim().CreateWithKeywords(keywords));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingSession> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingSession>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveToFileAsync(void* folder, void* fileName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().SaveToFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&folder), *reinterpret_cast<hstring const*>(&fileName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddLoggingChannel(void* loggingChannel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddLoggingChannel(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddLoggingChannelWithLevel(void* loggingChannel, int32_t maxLevel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddLoggingChannel(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&maxLevel));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveLoggingChannel(void* loggingChannel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveLoggingChannel(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::ILoggingChannel const*>(&loggingChannel));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingSessionFactory> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingSessionFactory>
    {
        int32_t __stdcall Create(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingSession>(this->shim().Create(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ILoggingTarget> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ILoggingTarget>
    {
        int32_t __stdcall IsEnabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEnabledWithLevel(int32_t level, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsEnabled(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEnabledWithLevelAndKeywords(int32_t level, int64_t keywords, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsEnabled(*reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level), keywords));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogEvent(void* eventName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogEvent(*reinterpret_cast<hstring const*>(&eventName));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogEventWithFields(void* eventName, void* fields) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogEvent(*reinterpret_cast<hstring const*>(&eventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogEventWithFieldsAndLevel(void* eventName, void* fields, int32_t level) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogEvent(*reinterpret_cast<hstring const*>(&eventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LogEventWithFieldsAndOptions(void* eventName, void* fields, int32_t level, void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogEvent(*reinterpret_cast<hstring const*>(&eventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartActivity(void* startEventName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingActivity>(this->shim().StartActivity(*reinterpret_cast<hstring const*>(&startEventName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartActivityWithFields(void* startEventName, void* fields, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingActivity>(this->shim().StartActivity(*reinterpret_cast<hstring const*>(&startEventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartActivityWithFieldsAndLevel(void* startEventName, void* fields, int32_t level, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingActivity>(this->shim().StartActivity(*reinterpret_cast<hstring const*>(&startEventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartActivityWithFieldsAndOptions(void* startEventName, void* fields, int32_t level, void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Diagnostics::LoggingActivity>(this->shim().StartActivity(*reinterpret_cast<hstring const*>(&startEventName), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingFields const*>(&fields), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingLevel const*>(&level), *reinterpret_cast<winrt::Windows::Foundation::Diagnostics::LoggingOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Foundation::Diagnostics::ITracingStatusChangedEventArgs> : produce_base<D, winrt::Windows::Foundation::Diagnostics::ITracingStatusChangedEventArgs>
    {
        int32_t __stdcall get_Enabled(bool* enabled) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *enabled = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TraceLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel>(this->shim().TraceLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Diagnostics
{
    constexpr auto operator|(ErrorOptions const left, ErrorOptions const right) noexcept
    {
        return static_cast<ErrorOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ErrorOptions& left, ErrorOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ErrorOptions const left, ErrorOptions const right) noexcept
    {
        return static_cast<ErrorOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ErrorOptions& left, ErrorOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ErrorOptions const value) noexcept
    {
        return static_cast<ErrorOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ErrorOptions const left, ErrorOptions const right) noexcept
    {
        return static_cast<ErrorOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ErrorOptions& left, ErrorOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto AsyncCausalityTracer::TraceOperationCreation(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, param::hstring const& operationName, uint64_t relatedContext)
    {
        impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TraceOperationCreation(traceLevel, source, platformId, operationId, operationName, relatedContext); });
    }
    inline auto AsyncCausalityTracer::TraceOperationCompletion(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, winrt::Windows::Foundation::AsyncStatus const& status)
    {
        impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TraceOperationCompletion(traceLevel, source, platformId, operationId, status); });
    }
    inline auto AsyncCausalityTracer::TraceOperationRelation(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, winrt::Windows::Foundation::Diagnostics::CausalityRelation const& relation)
    {
        impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TraceOperationRelation(traceLevel, source, platformId, operationId, relation); });
    }
    inline auto AsyncCausalityTracer::TraceSynchronousWorkStart(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::guid const& platformId, uint64_t operationId, winrt::Windows::Foundation::Diagnostics::CausalitySynchronousWork const& work)
    {
        impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TraceSynchronousWorkStart(traceLevel, source, platformId, operationId, work); });
    }
    inline auto AsyncCausalityTracer::TraceSynchronousWorkCompletion(winrt::Windows::Foundation::Diagnostics::CausalityTraceLevel const& traceLevel, winrt::Windows::Foundation::Diagnostics::CausalitySource const& source, winrt::Windows::Foundation::Diagnostics::CausalitySynchronousWork const& work)
    {
        impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TraceSynchronousWorkCompletion(traceLevel, source, work); });
    }
    inline auto AsyncCausalityTracer::TracingStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::Diagnostics::TracingStatusChangedEventArgs> const& handler)
    {
        return impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TracingStatusChanged(handler); });
    }
    inline AsyncCausalityTracer::TracingStatusChanged_revoker AsyncCausalityTracer::TracingStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::Diagnostics::TracingStatusChangedEventArgs> const& handler)
    {
        auto f = get_activation_factory<AsyncCausalityTracer, winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics>();
        return { f, f.TracingStatusChanged(handler) };
    }
    inline auto AsyncCausalityTracer::TracingStatusChanged(winrt::event_token const& cookie)
    {
        impl::call_factory<AsyncCausalityTracer, IAsyncCausalityTracerStatics>([&](IAsyncCausalityTracerStatics const& f) { return f.TracingStatusChanged(cookie); });
    }
    inline auto ErrorDetails::CreateFromHResultAsync(int32_t errorCode)
    {
        return impl::call_factory<ErrorDetails, IErrorDetailsStatics>([&](IErrorDetailsStatics const& f) { return f.CreateFromHResultAsync(errorCode); });
    }
    inline FileLoggingSession::FileLoggingSession(param::hstring const& name) :
        FileLoggingSession(impl::call_factory<FileLoggingSession, IFileLoggingSessionFactory>([&](IFileLoggingSessionFactory const& f) { return f.Create(name); }))
    {
    }
    inline LoggingActivity::LoggingActivity(param::hstring const& activityName, winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel) :
        LoggingActivity(impl::call_factory<LoggingActivity, ILoggingActivityFactory>([&](ILoggingActivityFactory const& f) { return f.CreateLoggingActivity(activityName, loggingChannel); }))
    {
    }
    inline LoggingActivity::LoggingActivity(param::hstring const& activityName, winrt::Windows::Foundation::Diagnostics::ILoggingChannel const& loggingChannel, winrt::Windows::Foundation::Diagnostics::LoggingLevel const& level) :
        LoggingActivity(impl::call_factory<LoggingActivity, ILoggingActivityFactory>([&](ILoggingActivityFactory const& f) { return f.CreateLoggingActivityWithLevel(activityName, loggingChannel, level); }))
    {
    }
    inline LoggingChannel::LoggingChannel(param::hstring const& name) :
        LoggingChannel(impl::call_factory<LoggingChannel, ILoggingChannelFactory>([&](ILoggingChannelFactory const& f) { return f.Create(name); }))
    {
    }
    inline LoggingChannel::LoggingChannel(param::hstring const& name, winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions const& options) :
        LoggingChannel(impl::call_factory<LoggingChannel, ILoggingChannelFactory2>([&](ILoggingChannelFactory2 const& f) { return f.CreateWithOptions(name, options); }))
    {
    }
    inline LoggingChannel::LoggingChannel(param::hstring const& name, winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions const& options, winrt::guid const& id) :
        LoggingChannel(impl::call_factory<LoggingChannel, ILoggingChannelFactory2>([&](ILoggingChannelFactory2 const& f) { return f.CreateWithOptionsAndId(name, options, id); }))
    {
    }
    inline LoggingChannelOptions::LoggingChannelOptions() :
        LoggingChannelOptions(impl::call_factory_cast<LoggingChannelOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), LoggingChannelOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LoggingChannelOptions>(); }))
    {
    }
    inline LoggingChannelOptions::LoggingChannelOptions(winrt::guid const& group) :
        LoggingChannelOptions(impl::call_factory<LoggingChannelOptions, ILoggingChannelOptionsFactory>([&](ILoggingChannelOptionsFactory const& f) { return f.Create(group); }))
    {
    }
    inline LoggingFields::LoggingFields() :
        LoggingFields(impl::call_factory_cast<LoggingFields(*)(winrt::Windows::Foundation::IActivationFactory const&), LoggingFields>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LoggingFields>(); }))
    {
    }
    inline LoggingOptions::LoggingOptions() :
        LoggingOptions(impl::call_factory_cast<LoggingOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), LoggingOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LoggingOptions>(); }))
    {
    }
    inline LoggingOptions::LoggingOptions(int64_t keywords) :
        LoggingOptions(impl::call_factory<LoggingOptions, ILoggingOptionsFactory>([&](ILoggingOptionsFactory const& f) { return f.CreateWithKeywords(keywords); }))
    {
    }
    inline LoggingSession::LoggingSession(param::hstring const& name) :
        LoggingSession(impl::call_factory<LoggingSession, ILoggingSessionFactory>([&](ILoggingSessionFactory const& f) { return f.Create(name); }))
    {
    }
    inline RuntimeBrokerErrorSettings::RuntimeBrokerErrorSettings() :
        RuntimeBrokerErrorSettings(impl::call_factory_cast<RuntimeBrokerErrorSettings(*)(winrt::Windows::Foundation::IActivationFactory const&), RuntimeBrokerErrorSettings>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RuntimeBrokerErrorSettings>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::IAsyncCausalityTracerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::IErrorDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::IErrorDetailsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::IErrorReportingSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::IFileLoggingSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::IFileLoggingSessionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILogFileGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingActivity> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingActivity2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingActivityFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingChannel2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingChannelFactory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingChannelOptionsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingFields> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingOptionsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingSessionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ILoggingTarget> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ITracingStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::AsyncCausalityTracer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::ErrorDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::FileLoggingSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LogFileGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LoggingActivity> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LoggingChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LoggingChannelOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LoggingFields> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LoggingOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::LoggingSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::RuntimeBrokerErrorSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Foundation::Diagnostics::TracingStatusChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
