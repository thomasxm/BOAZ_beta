// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_Preview_Communications_H
#define WINRT_Windows_UI_Core_Preview_Communications_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Core.Preview.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Core.Preview.Communications.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamCleanupRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewTeamViewCommand) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamCommandInvokedEventArgs<D>::Command() const
    {
        winrt::Windows::UI::Core::Preview::Communications::PreviewTeamViewCommand value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs)->get_Command(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamDeviceCredentials<D>::UserPrincipalName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials)->get_UserPrincipalName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamDeviceCredentials<D>::DomainUserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials)->get_DomainUserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamDeviceCredentials<D>::Password() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials)->get_Password(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamEndMeetingRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamJoinMeetingRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamJoinMeetingRequestedEventArgs<D>::MeetingUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs)->get_MeetingUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SetTitle(param::hstring const& title) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->SetTitle(*(void**)(&title)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::EnterFullScreen() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->EnterFullScreen());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::LeaveFullScreen() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->LeaveFullScreen());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::RequestForeground() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->RequestForeground());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::StartSharingScreen() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->StartSharingScreen());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::StopSharingScreen() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->StopSharingScreen());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::NotifyMeetingEnded(winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingKind const& kind) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->NotifyMeetingEnded(static_cast<int32_t>(kind)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::JoinMeetingWithUri(winrt::Windows::Foundation::Uri const& meetingUri) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->JoinMeetingWithUri(*(void**)(&meetingUri)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::MeetingUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->get_MeetingUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SharingScreenBounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->get_SharingScreenBounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsScreenSharing() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->get_IsScreenSharing(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsFullScreen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->get_IsFullScreen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewSystemState) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SystemState() const
    {
        winrt::Windows::UI::Core::Preview::Communications::PreviewSystemState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->get_SystemState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewMeetingInfoDisplayKind) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::MeetingInfoDisplayType() const
    {
        winrt::Windows::UI::Core::Preview::Communications::PreviewMeetingInfoDisplayKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->get_MeetingInfoDisplayType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::JoinMeetingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_JoinMeetingRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::JoinMeetingRequested_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::JoinMeetingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, JoinMeetingRequested_revoker>(this, JoinMeetingRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::JoinMeetingRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_JoinMeetingRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::EndMeetingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_EndMeetingRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::EndMeetingRequested_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::EndMeetingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, EndMeetingRequested_revoker>(this, EndMeetingRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::EndMeetingRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_EndMeetingRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CleanupRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_CleanupRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CleanupRequested_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CleanupRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CleanupRequested_revoker>(this, CleanupRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CleanupRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_CleanupRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SharingScreenBoundsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_SharingScreenBoundsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SharingScreenBoundsChanged_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SharingScreenBoundsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SharingScreenBoundsChanged_revoker>(this, SharingScreenBoundsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SharingScreenBoundsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_SharingScreenBoundsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsScreenSharingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_IsScreenSharingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsScreenSharingChanged_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsScreenSharingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsScreenSharingChanged_revoker>(this, IsScreenSharingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsScreenSharingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_IsScreenSharingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsFullScreenChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_IsFullScreenChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsFullScreenChanged_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsFullScreenChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsFullScreenChanged_revoker>(this, IsFullScreenChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::IsFullScreenChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_IsFullScreenChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CommandInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_CommandInvoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CommandInvoked_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CommandInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CommandInvoked_revoker>(this, CommandInvoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::CommandInvoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_CommandInvoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SystemStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->add_SystemStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SystemStateChanged_revoker consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SystemStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SystemStateChanged_revoker>(this, SystemStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView<D>::SystemStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView)->remove_SystemStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamView2<D>::SetButtonLabel(param::hstring const& label) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2)->SetButtonLabel(*(void**)(&label)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView) consume_Windows_UI_Core_Preview_Communications_IPreviewTeamViewStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics)->GetForCurrentView(&result));
        return winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs>
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
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs>
    {
        int32_t __stdcall get_Command(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamViewCommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials>
    {
        int32_t __stdcall get_UserPrincipalName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserPrincipalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainUserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DomainUserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Password(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Password());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs>
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
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs>
    {
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MeetingUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().MeetingUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView>
    {
        int32_t __stdcall SetTitle(void* title) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTitle(*reinterpret_cast<hstring const*>(&title));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnterFullScreen() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnterFullScreen();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LeaveFullScreen() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LeaveFullScreen();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestForeground() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestForeground();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartSharingScreen() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartSharingScreen();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopSharingScreen() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopSharingScreen();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyMeetingEnded(int32_t kind) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyMeetingEnded(*reinterpret_cast<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingKind const*>(&kind));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall JoinMeetingWithUri(void* meetingUri) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().JoinMeetingWithUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&meetingUri));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MeetingUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().MeetingUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingScreenBounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().SharingScreenBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsScreenSharing(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScreenSharing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsFullScreen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFullScreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::Preview::Communications::PreviewSystemState>(this->shim().SystemState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MeetingInfoDisplayType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::Preview::Communications::PreviewMeetingInfoDisplayKind>(this->shim().MeetingInfoDisplayType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_JoinMeetingRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().JoinMeetingRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_JoinMeetingRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().JoinMeetingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EndMeetingRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EndMeetingRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EndMeetingRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndMeetingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CleanupRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CleanupRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CleanupRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CleanupRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SharingScreenBoundsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SharingScreenBoundsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SharingScreenBoundsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SharingScreenBoundsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_IsScreenSharingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsScreenSharingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsScreenSharingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsScreenSharingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_IsFullScreenChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsFullScreenChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsFullScreenChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsFullScreenChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CommandInvoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CommandInvoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CommandInvoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SystemStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SystemStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SystemStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2>
    {
        int32_t __stdcall SetButtonLabel(void* label) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetButtonLabel(*reinterpret_cast<hstring const*>(&label));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics> : produce_base<D, winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics>
    {
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview::Communications
{
    inline PreviewTeamDeviceCredentials::PreviewTeamDeviceCredentials() :
        PreviewTeamDeviceCredentials(impl::call_factory_cast<PreviewTeamDeviceCredentials(*)(winrt::Windows::Foundation::IActivationFactory const&), PreviewTeamDeviceCredentials>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PreviewTeamDeviceCredentials>(); }))
    {
    }
    inline auto PreviewTeamView::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView(*)(IPreviewTeamViewStatics const&), PreviewTeamView, IPreviewTeamViewStatics>([](IPreviewTeamViewStatics const& f) { return f.GetForCurrentView(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCleanupRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamCommandInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamDeviceCredentials> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamEndMeetingRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamJoinMeetingRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamView2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::IPreviewTeamViewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCleanupRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamCommandInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamDeviceCredentials> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamEndMeetingRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamJoinMeetingRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::Communications::PreviewTeamView> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
