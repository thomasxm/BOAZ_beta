// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_UserActivities_Core_H
#define WINRT_Windows_ApplicationModel_UserActivities_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.UserActivities.h"
#include "winrt/impl/Windows.ApplicationModel.UserActivities.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserActivities.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::UserActivities::UserActivitySession) consume_Windows_ApplicationModel_UserActivities_Core_ICoreUserActivityManagerStatics<D>::CreateUserActivitySessionInBackground(winrt::Windows::ApplicationModel::UserActivities::UserActivity const& activity) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics)->CreateUserActivitySessionInBackground(*(void**)(&activity), &result));
        return winrt::Windows::ApplicationModel::UserActivities::UserActivitySession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_UserActivities_Core_ICoreUserActivityManagerStatics<D>::DeleteUserActivitySessionsInTimeRangeAsync(winrt::Windows::ApplicationModel::UserActivities::UserActivityChannel const& channel, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::Foundation::DateTime const& endTime) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics)->DeleteUserActivitySessionsInTimeRangeAsync(*(void**)(&channel), impl::bind_in(startTime), impl::bind_in(endTime), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics>
    {
        int32_t __stdcall CreateUserActivitySessionInBackground(void* activity, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::UserActivities::UserActivitySession>(this->shim().CreateUserActivitySessionInBackground(*reinterpret_cast<winrt::Windows::ApplicationModel::UserActivities::UserActivity const*>(&activity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteUserActivitySessionsInTimeRangeAsync(void* channel, int64_t startTime, int64_t endTime, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteUserActivitySessionsInTimeRangeAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::UserActivities::UserActivityChannel const*>(&channel), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&endTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserActivities::Core
{
    inline auto CoreUserActivityManager::CreateUserActivitySessionInBackground(winrt::Windows::ApplicationModel::UserActivities::UserActivity const& activity)
    {
        return impl::call_factory<CoreUserActivityManager, ICoreUserActivityManagerStatics>([&](ICoreUserActivityManagerStatics const& f) { return f.CreateUserActivitySessionInBackground(activity); });
    }
    inline auto CoreUserActivityManager::DeleteUserActivitySessionsInTimeRangeAsync(winrt::Windows::ApplicationModel::UserActivities::UserActivityChannel const& channel, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::Foundation::DateTime const& endTime)
    {
        return impl::call_factory<CoreUserActivityManager, ICoreUserActivityManagerStatics>([&](ICoreUserActivityManagerStatics const& f) { return f.DeleteUserActivitySessionsInTimeRangeAsync(channel, startTime, endTime); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::Core::ICoreUserActivityManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::UserActivities::Core::CoreUserActivityManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
