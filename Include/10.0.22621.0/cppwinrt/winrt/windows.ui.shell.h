// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Shell_H
#define WINRT_Windows_UI_Shell_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.StartScreen.2.h"
#include "winrt/impl/Windows.UI.Shell.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Shell_IAdaptiveCard<D>::ToJson() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IAdaptiveCard)->ToJson(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::IAdaptiveCard) consume_Windows_UI_Shell_IAdaptiveCardBuilderStatics<D>::CreateAdaptiveCardFromJson(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IAdaptiveCardBuilderStatics)->CreateAdaptiveCardFromJson(*(void**)(&value), &result));
        return winrt::Windows::UI::Shell::IAdaptiveCard{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Shell_IFocusSession<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSession)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IFocusSession<D>::End() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSession)->End());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_IFocusSessionManager<D>::IsFocusActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->get_IsFocusActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::FocusSession) consume_Windows_UI_Shell_IFocusSessionManager<D>::GetSession(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->GetSession(*(void**)(&id), &result));
        return winrt::Windows::UI::Shell::FocusSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::FocusSession) consume_Windows_UI_Shell_IFocusSessionManager<D>::TryStartFocusSession() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->TryStartFocusSession(&result));
        return winrt::Windows::UI::Shell::FocusSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::FocusSession) consume_Windows_UI_Shell_IFocusSessionManager<D>::TryStartFocusSession(winrt::Windows::Foundation::DateTime const& endTime) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->TryStartFocusSession2(impl::bind_in(endTime), &result));
        return winrt::Windows::UI::Shell::FocusSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IFocusSessionManager<D>::DeactivateFocus() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->DeactivateFocus());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IFocusSessionManager<D>::IsFocusActiveChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::FocusSessionManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->add_IsFocusActiveChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IFocusSessionManager<D>::IsFocusActiveChanged_revoker consume_Windows_UI_Shell_IFocusSessionManager<D>::IsFocusActiveChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::FocusSessionManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsFocusActiveChanged_revoker>(this, IsFocusActiveChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IFocusSessionManager<D>::IsFocusActiveChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManager)->remove_IsFocusActiveChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::FocusSessionManager) consume_Windows_UI_Shell_IFocusSessionManagerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManagerStatics)->GetDefault(&result));
        return winrt::Windows::UI::Shell::FocusSessionManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_IFocusSessionManagerStatics<D>::IsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IFocusSessionManagerStatics)->get_IsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_Shell_ISecurityAppManager<D>::Register(winrt::Windows::UI::Shell::SecurityAppKind const& kind, param::hstring const& displayName, winrt::Windows::Foundation::Uri const& detailsUri, bool registerPerUser) const
    {
        winrt::guid result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ISecurityAppManager)->Register(static_cast<int32_t>(kind), *(void**)(&displayName), *(void**)(&detailsUri), registerPerUser, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_ISecurityAppManager<D>::Unregister(winrt::Windows::UI::Shell::SecurityAppKind const& kind, winrt::guid const& guidRegistration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ISecurityAppManager)->Unregister(static_cast<int32_t>(kind), impl::bind_in(guidRegistration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_ISecurityAppManager<D>::UpdateState(winrt::Windows::UI::Shell::SecurityAppKind const& kind, winrt::guid const& guidRegistration, winrt::Windows::UI::Shell::SecurityAppState const& state, winrt::Windows::UI::Shell::SecurityAppSubstatus const& substatus, winrt::Windows::Foundation::Uri const& detailsUri) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ISecurityAppManager)->UpdateState(static_cast<int32_t>(kind), impl::bind_in(guidRegistration), static_cast<int32_t>(state), static_cast<int32_t>(substatus), *(void**)(&detailsUri)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowId) consume_Windows_UI_Shell_IShareWindowCommandEventArgs<D>::WindowId() const
    {
        winrt::Windows::UI::WindowId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandEventArgs)->get_WindowId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::ShareWindowCommand) consume_Windows_UI_Shell_IShareWindowCommandEventArgs<D>::Command() const
    {
        winrt::Windows::UI::Shell::ShareWindowCommand value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandEventArgs)->get_Command(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IShareWindowCommandEventArgs<D>::Command(winrt::Windows::UI::Shell::ShareWindowCommand const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandEventArgs)->put_Command(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::ReportCommandChanged() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->ReportCommandChanged());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::ShareWindowCommandSource, winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->add_CommandRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandRequested_revoker consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::ShareWindowCommandSource, winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CommandRequested_revoker>(this, CommandRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->remove_CommandRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::ShareWindowCommandSource, winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->add_CommandInvoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandInvoked_revoker consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::ShareWindowCommandSource, winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CommandInvoked_revoker>(this, CommandInvoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IShareWindowCommandSource<D>::CommandInvoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSource)->remove_CommandInvoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::ShareWindowCommandSource) consume_Windows_UI_Shell_IShareWindowCommandSourceStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IShareWindowCommandSourceStatics)->GetForCurrentView(&result));
        return winrt::Windows::UI::Shell::ShareWindowCommandSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_ITaskbarManager<D>::IsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager)->get_IsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_ITaskbarManager<D>::IsPinningAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager)->get_IsPinningAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager<D>::IsCurrentAppPinnedAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager)->IsCurrentAppPinnedAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager<D>::IsAppListEntryPinnedAsync(winrt::Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager)->IsAppListEntryPinnedAsync(*(void**)(&appListEntry), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager<D>::RequestPinCurrentAppAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager)->RequestPinCurrentAppAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager<D>::RequestPinAppListEntryAsync(winrt::Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager)->RequestPinAppListEntryAsync(*(void**)(&appListEntry), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager2<D>::IsSecondaryTilePinnedAsync(param::hstring const& tileId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager2)->IsSecondaryTilePinnedAsync(*(void**)(&tileId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager2<D>::RequestPinSecondaryTileAsync(winrt::Windows::UI::StartScreen::SecondaryTile const& secondaryTile) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager2)->RequestPinSecondaryTileAsync(*(void**)(&secondaryTile), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Shell_ITaskbarManager2<D>::TryUnpinSecondaryTileAsync(param::hstring const& tileId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManager2)->TryUnpinSecondaryTileAsync(*(void**)(&tileId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::TaskbarManager) consume_Windows_UI_Shell_ITaskbarManagerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::ITaskbarManagerStatics)->GetDefault(&result));
        return winrt::Windows::UI::Shell::TaskbarManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Shell_IWindowTab<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->get_Tag(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTab<D>::Tag(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Shell_IWindowTab<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTab<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabIcon) consume_Windows_UI_Shell_IWindowTab<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->get_Icon(&value));
        return winrt::Windows::UI::Shell::WindowTabIcon{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTab<D>::Icon(winrt::Windows::UI::Shell::WindowTabIcon const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->put_Icon(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Shell_IWindowTab<D>::TreatAsSecondaryTileId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->get_TreatAsSecondaryTileId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTab<D>::TreatAsSecondaryTileId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->put_TreatAsSecondaryTileId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabGroup) consume_Windows_UI_Shell_IWindowTab<D>::Group() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->get_Group(&value));
        return winrt::Windows::UI::Shell::WindowTabGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTab<D>::Group(winrt::Windows::UI::Shell::WindowTabGroup const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->put_Group(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTab<D>::ReportThumbnailAvailable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTab)->ReportThumbnailAvailable());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTab) consume_Windows_UI_Shell_IWindowTabCloseRequestedEventArgs<D>::Tab() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabCloseRequestedEventArgs)->get_Tab(&value));
        return winrt::Windows::UI::Shell::WindowTab{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabCollection<D>::MoveTab(winrt::Windows::UI::Shell::WindowTab const& tab, uint32_t index) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabCollection)->MoveTab(*(void**)(&tab), index));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Shell_IWindowTabGroup<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabGroup)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabGroup<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabGroup)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabIcon) consume_Windows_UI_Shell_IWindowTabGroup<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabGroup)->get_Icon(&value));
        return winrt::Windows::UI::Shell::WindowTabIcon{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabGroup<D>::Icon(winrt::Windows::UI::Shell::WindowTabIcon const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabGroup)->put_Icon(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabIcon) consume_Windows_UI_Shell_IWindowTabIconStatics<D>::CreateFromFontGlyph(param::hstring const& glyph, param::hstring const& fontFamily) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabIconStatics)->CreateFromFontGlyph(*(void**)(&glyph), *(void**)(&fontFamily), &result));
        return winrt::Windows::UI::Shell::WindowTabIcon{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabIcon) consume_Windows_UI_Shell_IWindowTabIconStatics<D>::CreateFromFontGlyph(param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabIconStatics)->CreateFromFontGlyphWithUri(*(void**)(&glyph), *(void**)(&fontFamily), *(void**)(&fontUri), &result));
        return winrt::Windows::UI::Shell::WindowTabIcon{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabIcon) consume_Windows_UI_Shell_IWindowTabIconStatics<D>::CreateFromImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& image) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabIconStatics)->CreateFromImage(*(void**)(&image), &result));
        return winrt::Windows::UI::Shell::WindowTabIcon{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabCollection) consume_Windows_UI_Shell_IWindowTabManager<D>::Tabs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->get_Tabs(&value));
        return winrt::Windows::UI::Shell::WindowTabCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabManager<D>::SetActiveTab(winrt::Windows::UI::Shell::WindowTab const& tab) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->SetActiveTab(*(void**)(&tab)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IWindowTabManager<D>::TabSwitchRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabSwitchRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->add_TabSwitchRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IWindowTabManager<D>::TabSwitchRequested_revoker consume_Windows_UI_Shell_IWindowTabManager<D>::TabSwitchRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabSwitchRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TabSwitchRequested_revoker>(this, TabSwitchRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabManager<D>::TabSwitchRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->remove_TabSwitchRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IWindowTabManager<D>::TabCloseRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabCloseRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->add_TabCloseRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IWindowTabManager<D>::TabCloseRequested_revoker consume_Windows_UI_Shell_IWindowTabManager<D>::TabCloseRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabCloseRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TabCloseRequested_revoker>(this, TabCloseRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabManager<D>::TabCloseRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->remove_TabCloseRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IWindowTabManager<D>::TabTearOutRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabTearOutRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->add_TabTearOutRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IWindowTabManager<D>::TabTearOutRequested_revoker consume_Windows_UI_Shell_IWindowTabManager<D>::TabTearOutRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabTearOutRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TabTearOutRequested_revoker>(this, TabTearOutRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabManager<D>::TabTearOutRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->remove_TabTearOutRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Shell_IWindowTabManager<D>::TabThumbnailRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabThumbnailRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->add_TabThumbnailRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Shell_IWindowTabManager<D>::TabThumbnailRequested_revoker consume_Windows_UI_Shell_IWindowTabManager<D>::TabThumbnailRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabThumbnailRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TabThumbnailRequested_revoker>(this, TabThumbnailRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabManager<D>::TabThumbnailRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManager)->remove_TabThumbnailRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTabManager) consume_Windows_UI_Shell_IWindowTabManagerStatics<D>::GetForWindow(winrt::Windows::UI::WindowId const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManagerStatics)->GetForWindow(impl::bind_in(id), &result));
        return winrt::Windows::UI::Shell::WindowTabManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_IWindowTabManagerStatics<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManagerStatics)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_IWindowTabManagerStatics<D>::IsTabTearOutSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabManagerStatics)->IsTabTearOutSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTab) consume_Windows_UI_Shell_IWindowTabSwitchRequestedEventArgs<D>::Tab() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabSwitchRequestedEventArgs)->get_Tab(&value));
        return winrt::Windows::UI::Shell::WindowTab{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTab) consume_Windows_UI_Shell_IWindowTabTearOutRequestedEventArgs<D>::Tab() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs)->get_Tab(&value));
        return winrt::Windows::UI::Shell::WindowTab{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_UI_Shell_IWindowTabTearOutRequestedEventArgs<D>::WindowId() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs)->get_WindowId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabTearOutRequestedEventArgs<D>::WindowId(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs)->put_WindowId(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Shell_IWindowTabTearOutRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Shell::WindowTab) consume_Windows_UI_Shell_IWindowTabThumbnailRequestedEventArgs<D>::Tab() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs)->get_Tab(&value));
        return winrt::Windows::UI::Shell::WindowTab{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapSize) consume_Windows_UI_Shell_IWindowTabThumbnailRequestedEventArgs<D>::RequestedSize() const
    {
        winrt::Windows::Graphics::Imaging::BitmapSize value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs)->get_RequestedSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_UI_Shell_IWindowTabThumbnailRequestedEventArgs<D>::Image() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs)->get_Image(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Shell_IWindowTabThumbnailRequestedEventArgs<D>::Image(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs)->put_Image(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Shell_IWindowTabThumbnailRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Shell_IWindowTabThumbnailRequestedEventArgs<D>::IsCompositedOnWindow() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs)->get_IsCompositedOnWindow(&value));
        return value;
    }
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IAdaptiveCard> : produce_base<D, winrt::Windows::UI::Shell::IAdaptiveCard>
    {
        int32_t __stdcall ToJson(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().ToJson());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IAdaptiveCardBuilderStatics> : produce_base<D, winrt::Windows::UI::Shell::IAdaptiveCardBuilderStatics>
    {
        int32_t __stdcall CreateAdaptiveCardFromJson(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::IAdaptiveCard>(this->shim().CreateAdaptiveCardFromJson(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IFocusSession> : produce_base<D, winrt::Windows::UI::Shell::IFocusSession>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall End() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().End();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IFocusSessionManager> : produce_base<D, winrt::Windows::UI::Shell::IFocusSessionManager>
    {
        int32_t __stdcall get_IsFocusActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFocusActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSession(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::FocusSession>(this->shim().GetSession(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStartFocusSession(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::FocusSession>(this->shim().TryStartFocusSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStartFocusSession2(int64_t endTime, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::FocusSession>(this->shim().TryStartFocusSession(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&endTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeactivateFocus() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeactivateFocus();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_IsFocusActiveChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsFocusActiveChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::FocusSessionManager, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsFocusActiveChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsFocusActiveChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IFocusSessionManagerStatics> : produce_base<D, winrt::Windows::UI::Shell::IFocusSessionManagerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::FocusSessionManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::ISecurityAppManager> : produce_base<D, winrt::Windows::UI::Shell::ISecurityAppManager>
    {
        int32_t __stdcall Register(int32_t kind, void* displayName, void* detailsUri, bool registerPerUser, winrt::guid* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::guid>(this->shim().Register(*reinterpret_cast<winrt::Windows::UI::Shell::SecurityAppKind const*>(&kind), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&detailsUri), registerPerUser));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Unregister(int32_t kind, winrt::guid guidRegistration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Unregister(*reinterpret_cast<winrt::Windows::UI::Shell::SecurityAppKind const*>(&kind), *reinterpret_cast<winrt::guid const*>(&guidRegistration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateState(int32_t kind, winrt::guid guidRegistration, int32_t state, int32_t substatus, void* detailsUri) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateState(*reinterpret_cast<winrt::Windows::UI::Shell::SecurityAppKind const*>(&kind), *reinterpret_cast<winrt::guid const*>(&guidRegistration), *reinterpret_cast<winrt::Windows::UI::Shell::SecurityAppState const*>(&state), *reinterpret_cast<winrt::Windows::UI::Shell::SecurityAppSubstatus const*>(&substatus), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&detailsUri));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IShareWindowCommandEventArgs> : produce_base<D, winrt::Windows::UI::Shell::IShareWindowCommandEventArgs>
    {
        int32_t __stdcall get_WindowId(struct struct_Windows_UI_WindowId* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::WindowId>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowId>(this->shim().WindowId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Command(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::ShareWindowCommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Command(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Command(*reinterpret_cast<winrt::Windows::UI::Shell::ShareWindowCommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IShareWindowCommandSource> : produce_base<D, winrt::Windows::UI::Shell::IShareWindowCommandSource>
    {
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
        int32_t __stdcall ReportCommandChanged() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCommandChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CommandRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CommandRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::ShareWindowCommandSource, winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CommandRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CommandInvoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CommandInvoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::ShareWindowCommandSource, winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CommandInvoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IShareWindowCommandSourceStatics> : produce_base<D, winrt::Windows::UI::Shell::IShareWindowCommandSourceStatics>
    {
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::ShareWindowCommandSource>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::ITaskbarManager> : produce_base<D, winrt::Windows::UI::Shell::ITaskbarManager>
    {
        int32_t __stdcall get_IsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPinningAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPinningAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsCurrentAppPinnedAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsCurrentAppPinnedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsAppListEntryPinnedAsync(void* appListEntry, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsAppListEntryPinnedAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinCurrentAppAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinCurrentAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinAppListEntryAsync(void* appListEntry, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinAppListEntryAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::ITaskbarManager2> : produce_base<D, winrt::Windows::UI::Shell::ITaskbarManager2>
    {
        int32_t __stdcall IsSecondaryTilePinnedAsync(void* tileId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSecondaryTilePinnedAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinSecondaryTileAsync(void* secondaryTile, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinSecondaryTileAsync(*reinterpret_cast<winrt::Windows::UI::StartScreen::SecondaryTile const*>(&secondaryTile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUnpinSecondaryTileAsync(void* tileId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUnpinSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::ITaskbarManagerDesktopAppSupportStatics> : produce_base<D, winrt::Windows::UI::Shell::ITaskbarManagerDesktopAppSupportStatics>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::ITaskbarManagerStatics> : produce_base<D, winrt::Windows::UI::Shell::ITaskbarManagerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::TaskbarManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTab> : produce_base<D, winrt::Windows::UI::Shell::IWindowTab>
    {
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTabIcon>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Icon(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Icon(*reinterpret_cast<winrt::Windows::UI::Shell::WindowTabIcon const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TreatAsSecondaryTileId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TreatAsSecondaryTileId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TreatAsSecondaryTileId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TreatAsSecondaryTileId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Group(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTabGroup>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Group(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Group(*reinterpret_cast<winrt::Windows::UI::Shell::WindowTabGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportThumbnailAvailable() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportThumbnailAvailable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabCloseRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabCloseRequestedEventArgs>
    {
        int32_t __stdcall get_Tab(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTab>(this->shim().Tab());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabCollection> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabCollection>
    {
        int32_t __stdcall MoveTab(void* tab, uint32_t index) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MoveTab(*reinterpret_cast<winrt::Windows::UI::Shell::WindowTab const*>(&tab), index);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabGroup> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabGroup>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTabIcon>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Icon(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Icon(*reinterpret_cast<winrt::Windows::UI::Shell::WindowTabIcon const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabIcon> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabIcon>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabIconStatics> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabIconStatics>
    {
        int32_t __stdcall CreateFromFontGlyph(void* glyph, void* fontFamily, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::WindowTabIcon>(this->shim().CreateFromFontGlyph(*reinterpret_cast<hstring const*>(&glyph), *reinterpret_cast<hstring const*>(&fontFamily)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromFontGlyphWithUri(void* glyph, void* fontFamily, void* fontUri, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::WindowTabIcon>(this->shim().CreateFromFontGlyph(*reinterpret_cast<hstring const*>(&glyph), *reinterpret_cast<hstring const*>(&fontFamily), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&fontUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromImage(void* image, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::WindowTabIcon>(this->shim().CreateFromImage(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&image)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabManager> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabManager>
    {
        int32_t __stdcall get_Tabs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTabCollection>(this->shim().Tabs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetActiveTab(void* tab) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetActiveTab(*reinterpret_cast<winrt::Windows::UI::Shell::WindowTab const*>(&tab));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_TabSwitchRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TabSwitchRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabSwitchRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TabSwitchRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabSwitchRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TabCloseRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TabCloseRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabCloseRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TabCloseRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabCloseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TabTearOutRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TabTearOutRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabTearOutRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TabTearOutRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabTearOutRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TabThumbnailRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TabThumbnailRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Shell::WindowTabManager, winrt::Windows::UI::Shell::WindowTabThumbnailRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TabThumbnailRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabThumbnailRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabManagerStatics> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabManagerStatics>
    {
        int32_t __stdcall GetForWindow(struct struct_Windows_UI_WindowId id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Shell::WindowTabManager>(this->shim().GetForWindow(*reinterpret_cast<winrt::Windows::UI::WindowId const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsTabTearOutSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsTabTearOutSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabSwitchRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabSwitchRequestedEventArgs>
    {
        int32_t __stdcall get_Tab(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTab>(this->shim().Tab());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs>
    {
        int32_t __stdcall get_Tab(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTab>(this->shim().Tab());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WindowId(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().WindowId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WindowId(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WindowId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
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
    struct produce<D, winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs>
    {
        int32_t __stdcall get_Tab(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Shell::WindowTab>(this->shim().Tab());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedSize(struct struct_Windows_Graphics_Imaging_BitmapSize* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::Imaging::BitmapSize>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::BitmapSize>(this->shim().RequestedSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Image(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Image(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Image(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCompositedOnWindow(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCompositedOnWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Shell
{
    inline auto AdaptiveCardBuilder::CreateAdaptiveCardFromJson(param::hstring const& value)
    {
        return impl::call_factory<AdaptiveCardBuilder, IAdaptiveCardBuilderStatics>([&](IAdaptiveCardBuilderStatics const& f) { return f.CreateAdaptiveCardFromJson(value); });
    }
    inline auto FocusSessionManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Shell::FocusSessionManager(*)(IFocusSessionManagerStatics const&), FocusSessionManager, IFocusSessionManagerStatics>([](IFocusSessionManagerStatics const& f) { return f.GetDefault(); });
    }
    inline auto FocusSessionManager::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IFocusSessionManagerStatics const&), FocusSessionManager, IFocusSessionManagerStatics>([](IFocusSessionManagerStatics const& f) { return f.IsSupported(); });
    }
    inline SecurityAppManager::SecurityAppManager() :
        SecurityAppManager(impl::call_factory_cast<SecurityAppManager(*)(winrt::Windows::Foundation::IActivationFactory const&), SecurityAppManager>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SecurityAppManager>(); }))
    {
    }
    inline auto ShareWindowCommandSource::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Shell::ShareWindowCommandSource(*)(IShareWindowCommandSourceStatics const&), ShareWindowCommandSource, IShareWindowCommandSourceStatics>([](IShareWindowCommandSourceStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto TaskbarManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Shell::TaskbarManager(*)(ITaskbarManagerStatics const&), TaskbarManager, ITaskbarManagerStatics>([](ITaskbarManagerStatics const& f) { return f.GetDefault(); });
    }
    inline WindowTab::WindowTab() :
        WindowTab(impl::call_factory_cast<WindowTab(*)(winrt::Windows::Foundation::IActivationFactory const&), WindowTab>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WindowTab>(); }))
    {
    }
    inline WindowTabGroup::WindowTabGroup() :
        WindowTabGroup(impl::call_factory_cast<WindowTabGroup(*)(winrt::Windows::Foundation::IActivationFactory const&), WindowTabGroup>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WindowTabGroup>(); }))
    {
    }
    inline auto WindowTabIcon::CreateFromFontGlyph(param::hstring const& glyph, param::hstring const& fontFamily)
    {
        return impl::call_factory<WindowTabIcon, IWindowTabIconStatics>([&](IWindowTabIconStatics const& f) { return f.CreateFromFontGlyph(glyph, fontFamily); });
    }
    inline auto WindowTabIcon::CreateFromFontGlyph(param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri)
    {
        return impl::call_factory<WindowTabIcon, IWindowTabIconStatics>([&](IWindowTabIconStatics const& f) { return f.CreateFromFontGlyph(glyph, fontFamily, fontUri); });
    }
    inline auto WindowTabIcon::CreateFromImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& image)
    {
        return impl::call_factory<WindowTabIcon, IWindowTabIconStatics>([&](IWindowTabIconStatics const& f) { return f.CreateFromImage(image); });
    }
    inline auto WindowTabManager::GetForWindow(winrt::Windows::UI::WindowId const& id)
    {
        return impl::call_factory<WindowTabManager, IWindowTabManagerStatics>([&](IWindowTabManagerStatics const& f) { return f.GetForWindow(id); });
    }
    inline auto WindowTabManager::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IWindowTabManagerStatics const&), WindowTabManager, IWindowTabManagerStatics>([](IWindowTabManagerStatics const& f) { return f.IsSupported(); });
    }
    inline auto WindowTabManager::IsTabTearOutSupported()
    {
        return impl::call_factory_cast<bool(*)(IWindowTabManagerStatics const&), WindowTabManager, IWindowTabManagerStatics>([](IWindowTabManagerStatics const& f) { return f.IsTabTearOutSupported(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Shell::IAdaptiveCard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IAdaptiveCardBuilderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IFocusSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IFocusSessionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IFocusSessionManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ISecurityAppManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IShareWindowCommandEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IShareWindowCommandSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IShareWindowCommandSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManagerDesktopAppSupportStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ITaskbarManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTab> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabCloseRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabIcon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabIconStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabSwitchRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::AdaptiveCardBuilder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::FocusSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::FocusSessionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::SecurityAppManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ShareWindowCommandEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::ShareWindowCommandSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::TaskbarManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTab> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabCloseRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabIcon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabSwitchRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabTearOutRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Shell::WindowTabThumbnailRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
