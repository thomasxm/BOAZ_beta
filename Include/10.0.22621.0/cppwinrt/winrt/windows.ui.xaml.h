// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_H
#define WINRT_Windows_UI_Xaml_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.DragDrop.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Data.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Imaging.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTrigger)->get_MinWindowWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowWidth(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTrigger)->put_MinWindowWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTrigger)->get_MinWindowHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowHeight(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTrigger)->put_MinWindowHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::AdaptiveTrigger) consume_Windows_UI_Xaml_IAdaptiveTriggerFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTriggerFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::AdaptiveTrigger{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IAdaptiveTriggerStatics<D>::MinWindowWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics)->get_MinWindowWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IAdaptiveTriggerStatics<D>::MinWindowHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics)->get_MinWindowHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ResourceDictionary) consume_Windows_UI_Xaml_IApplication<D>::Resources() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->get_Resources(&value));
        return winrt::Windows::UI::Xaml::ResourceDictionary{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication<D>::Resources(winrt::Windows::UI::Xaml::ResourceDictionary const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->put_Resources(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DebugSettings) consume_Windows_UI_Xaml_IApplication<D>::DebugSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->get_DebugSettings(&value));
        return winrt::Windows::UI::Xaml::DebugSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ApplicationTheme) consume_Windows_UI_Xaml_IApplication<D>::RequestedTheme() const
    {
        winrt::Windows::UI::Xaml::ApplicationTheme value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->get_RequestedTheme(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication<D>::RequestedTheme(winrt::Windows::UI::Xaml::ApplicationTheme const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->put_RequestedTheme(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IApplication<D>::UnhandledException(winrt::Windows::UI::Xaml::UnhandledExceptionEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->add_UnhandledException(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IApplication<D>::UnhandledException_revoker consume_Windows_UI_Xaml_IApplication<D>::UnhandledException(auto_revoke_t, winrt::Windows::UI::Xaml::UnhandledExceptionEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, UnhandledException_revoker>(this, UnhandledException(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication<D>::UnhandledException(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->remove_UnhandledException(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IApplication<D>::Suspending(winrt::Windows::UI::Xaml::SuspendingEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->add_Suspending(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IApplication<D>::Suspending_revoker consume_Windows_UI_Xaml_IApplication<D>::Suspending(auto_revoke_t, winrt::Windows::UI::Xaml::SuspendingEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Suspending_revoker>(this, Suspending(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication<D>::Suspending(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->remove_Suspending(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IApplication<D>::Resuming(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->add_Resuming(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IApplication<D>::Resuming_revoker consume_Windows_UI_Xaml_IApplication<D>::Resuming(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Resuming_revoker>(this, Resuming(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication<D>::Resuming(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->remove_Resuming(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication<D>::Exit() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication)->Exit());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusVisualKind) consume_Windows_UI_Xaml_IApplication2<D>::FocusVisualKind() const
    {
        winrt::Windows::UI::Xaml::FocusVisualKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->get_FocusVisualKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication2<D>::FocusVisualKind(winrt::Windows::UI::Xaml::FocusVisualKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->put_FocusVisualKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ApplicationRequiresPointerMode) consume_Windows_UI_Xaml_IApplication2<D>::RequiresPointerMode() const
    {
        winrt::Windows::UI::Xaml::ApplicationRequiresPointerMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->get_RequiresPointerMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication2<D>::RequiresPointerMode(winrt::Windows::UI::Xaml::ApplicationRequiresPointerMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->put_RequiresPointerMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground(winrt::Windows::UI::Xaml::LeavingBackgroundEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->add_LeavingBackground(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground_revoker consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground(auto_revoke_t, winrt::Windows::UI::Xaml::LeavingBackgroundEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, LeavingBackground_revoker>(this, LeavingBackground(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->remove_LeavingBackground(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground(winrt::Windows::UI::Xaml::EnteredBackgroundEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->add_EnteredBackground(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground_revoker consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground(auto_revoke_t, winrt::Windows::UI::Xaml::EnteredBackgroundEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, EnteredBackground_revoker>(this, EnteredBackground(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication2)->remove_EnteredBackground(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ApplicationHighContrastAdjustment) consume_Windows_UI_Xaml_IApplication3<D>::HighContrastAdjustment() const
    {
        winrt::Windows::UI::Xaml::ApplicationHighContrastAdjustment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication3)->get_HighContrastAdjustment(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplication3<D>::HighContrastAdjustment(winrt::Windows::UI::Xaml::ApplicationHighContrastAdjustment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplication3)->put_HighContrastAdjustment(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Application) consume_Windows_UI_Xaml_IApplicationFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Application{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnActivated(winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnLaunched(winrt::Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnLaunched(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnFileActivated(winrt::Windows::ApplicationModel::Activation::FileActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnFileActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnSearchActivated(winrt::Windows::ApplicationModel::Activation::SearchActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnSearchActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnShareTargetActivated(winrt::Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnShareTargetActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnFileOpenPickerActivated(winrt::Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnFileOpenPickerActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnFileSavePickerActivated(winrt::Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnFileSavePickerActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnCachedFileUpdaterActivated(winrt::Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnCachedFileUpdaterActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnWindowCreated(winrt::Windows::UI::Xaml::WindowCreatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides)->OnWindowCreated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationOverrides2<D>::OnBackgroundActivated(winrt::Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationOverrides2)->OnBackgroundActivated(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Application) consume_Windows_UI_Xaml_IApplicationStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationStatics)->get_Current(&value));
        return winrt::Windows::UI::Xaml::Application{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationStatics<D>::Start(winrt::Windows::UI::Xaml::ApplicationInitializationCallback const& callback) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationStatics)->Start(*(void**)(&callback)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationStatics<D>::LoadComponent(winrt::Windows::Foundation::IInspectable const& component, winrt::Windows::Foundation::Uri const& resourceLocator) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationStatics)->LoadComponent(*(void**)(&component), *(void**)(&resourceLocator)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IApplicationStatics<D>::LoadComponent(winrt::Windows::Foundation::IInspectable const& component, winrt::Windows::Foundation::Uri const& resourceLocator, winrt::Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const& componentResourceLocation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IApplicationStatics)->LoadComponentWithResourceLocation(*(void**)(&component), *(void**)(&resourceLocator), static_cast<int32_t>(componentResourceLocation)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IBindingFailedEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBindingFailedEventArgs)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::AnimationDesired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions)->get_AnimationDesired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::AnimationDesired(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions)->put_AnimationDesired(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>) consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::TargetRect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions)->get_TargetRect(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::TargetRect(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions)->put_TargetRect(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalAlignmentRatio() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->get_HorizontalAlignmentRatio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalAlignmentRatio(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->put_HorizontalAlignmentRatio(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalAlignmentRatio() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->get_VerticalAlignmentRatio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalAlignmentRatio(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->put_VerticalAlignmentRatio(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->put_HorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewOptions2)->put_VerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_TargetElement(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetElement(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_TargetElement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::AnimationDesired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_AnimationDesired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::AnimationDesired(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_AnimationDesired(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_TargetRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetRect(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_TargetRect(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::HorizontalAlignmentRatio() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_HorizontalAlignmentRatio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::VerticalAlignmentRatio() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_VerticalAlignmentRatio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::HorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_HorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::VerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_VerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Xaml_IBrushTransition<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBrushTransition)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IBrushTransition<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBrushTransition)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::BrushTransition) consume_Windows_UI_Xaml_IBrushTransitionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IBrushTransitionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::BrushTransition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_AltHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_AltHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_AltLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_AltLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMedium() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_AltMedium(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMedium(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_AltMedium(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_AltMediumHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_AltMediumHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_AltMediumLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_AltMediumLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_BaseHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_BaseHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_BaseLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_BaseLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMedium() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_BaseMedium(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMedium(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_BaseMedium(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_BaseMediumHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_BaseMediumHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_BaseMediumLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_BaseMediumLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeAltLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeAltLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeAltLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeAltLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMediumLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackMediumLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMediumLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackMediumLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMedium() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackMedium(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMedium(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackMedium(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeDisabledHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeDisabledHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeDisabledLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeDisabledLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeHigh() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeHigh(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeHigh(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeHigh(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMedium() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeMedium(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMedium(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeMedium(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMediumLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeMediumLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMediumLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeMediumLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeWhite() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeWhite(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeWhite(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeWhite(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeGray() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ChromeGray(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeGray(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ChromeGray(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ListLow(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListLow(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ListLow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListMedium() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ListMedium(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListMedium(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ListMedium(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ErrorText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_ErrorText(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::ErrorText(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_ErrorText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_IColorPaletteResources<D>::Accent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->get_Accent(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IColorPaletteResources<D>::Accent(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResources)->put_Accent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ColorPaletteResources) consume_Windows_UI_Xaml_IColorPaletteResourcesFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IColorPaletteResourcesFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::ColorPaletteResources{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::CornerRadius) consume_Windows_UI_Xaml_ICornerRadiusHelperStatics<D>::FromRadii(double topLeft, double topRight, double bottomRight, double bottomLeft) const
    {
        winrt::Windows::UI::Xaml::CornerRadius result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics)->FromRadii(topLeft, topRight, bottomRight, bottomLeft, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::CornerRadius) consume_Windows_UI_Xaml_ICornerRadiusHelperStatics<D>::FromUniformRadius(double uniformRadius) const
    {
        winrt::Windows::UI::Xaml::CornerRadius result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics)->FromUniformRadius(uniformRadius, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDataContextChangedEventArgs<D>::NewValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataContextChangedEventArgs)->get_NewValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDataContextChangedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataContextChangedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDataContextChangedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataContextChangedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_IDataTemplate<D>::LoadContent() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplate)->LoadContent(&result));
        return winrt::Windows::UI::Xaml::DependencyObject{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDataTemplateExtension<D>::ResetTemplate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateExtension)->ResetTemplate());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDataTemplateExtension<D>::ProcessBinding(uint32_t phase) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateExtension)->ProcessBinding(phase, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_IDataTemplateExtension<D>::ProcessBindings(winrt::Windows::UI::Xaml::Controls::ContainerContentChangingEventArgs const& arg) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateExtension)->ProcessBindings(*(void**)(&arg), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DataTemplate) consume_Windows_UI_Xaml_IDataTemplateFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::DataTemplate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDataTemplateKey<D>::DataType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateKey)->get_DataType(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDataTemplateKey<D>::DataType(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateKey)->put_DataType(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DataTemplateKey) consume_Windows_UI_Xaml_IDataTemplateKeyFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateKeyFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::DataTemplateKey{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DataTemplateKey) consume_Windows_UI_Xaml_IDataTemplateKeyFactory<D>::CreateInstanceWithType(winrt::Windows::Foundation::IInspectable const& dataType, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateKeyFactory)->CreateInstanceWithType(*(void**)(&dataType), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::DataTemplateKey{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IDataTemplateStatics2<D>::ExtensionInstanceProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateStatics2)->get_ExtensionInstanceProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::IDataTemplateExtension) consume_Windows_UI_Xaml_IDataTemplateStatics2<D>::GetExtensionInstance(winrt::Windows::UI::Xaml::FrameworkElement const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateStatics2)->GetExtensionInstance(*(void**)(&element), &result));
        return winrt::Windows::UI::Xaml::IDataTemplateExtension{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDataTemplateStatics2<D>::SetExtensionInstance(winrt::Windows::UI::Xaml::FrameworkElement const& element, winrt::Windows::UI::Xaml::IDataTemplateExtension const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDataTemplateStatics2)->SetExtensionInstance(*(void**)(&element), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDebugSettings<D>::EnableFrameRateCounter() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->get_EnableFrameRateCounter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings<D>::EnableFrameRateCounter(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->put_EnableFrameRateCounter(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDebugSettings<D>::IsBindingTracingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->get_IsBindingTracingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings<D>::IsBindingTracingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->put_IsBindingTracingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDebugSettings<D>::IsOverdrawHeatMapEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->get_IsOverdrawHeatMapEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings<D>::IsOverdrawHeatMapEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->put_IsOverdrawHeatMapEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed(winrt::Windows::UI::Xaml::BindingFailedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->add_BindingFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed_revoker consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed(auto_revoke_t, winrt::Windows::UI::Xaml::BindingFailedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, BindingFailed_revoker>(this, BindingFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings)->remove_BindingFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDebugSettings2<D>::EnableRedrawRegions() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings2)->get_EnableRedrawRegions(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings2<D>::EnableRedrawRegions(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings2)->put_EnableRedrawRegions(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDebugSettings3<D>::IsTextPerformanceVisualizationEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings3)->get_IsTextPerformanceVisualizationEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings3<D>::IsTextPerformanceVisualizationEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings3)->put_IsTextPerformanceVisualizationEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDebugSettings4<D>::FailFastOnErrors() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings4)->get_FailFastOnErrors(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDebugSettings4<D>::FailFastOnErrors(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDebugSettings4)->put_FailFastOnErrors(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDependencyObject<D>::GetValue(winrt::Windows::UI::Xaml::DependencyProperty const& dp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject)->GetValue(*(void**)(&dp), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDependencyObject<D>::SetValue(winrt::Windows::UI::Xaml::DependencyProperty const& dp, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject)->SetValue(*(void**)(&dp), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDependencyObject<D>::ClearValue(winrt::Windows::UI::Xaml::DependencyProperty const& dp) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject)->ClearValue(*(void**)(&dp)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDependencyObject<D>::ReadLocalValue(winrt::Windows::UI::Xaml::DependencyProperty const& dp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject)->ReadLocalValue(*(void**)(&dp), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDependencyObject<D>::GetAnimationBaseValue(winrt::Windows::UI::Xaml::DependencyProperty const& dp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject)->GetAnimationBaseValue(*(void**)(&dp), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcher) consume_Windows_UI_Xaml_IDependencyObject<D>::Dispatcher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject)->get_Dispatcher(&value));
        return winrt::Windows::UI::Core::CoreDispatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_UI_Xaml_IDependencyObject2<D>::RegisterPropertyChangedCallback(winrt::Windows::UI::Xaml::DependencyProperty const& dp, winrt::Windows::UI::Xaml::DependencyPropertyChangedCallback const& callback) const
    {
        int64_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject2)->RegisterPropertyChangedCallback(*(void**)(&dp), *(void**)(&callback), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDependencyObject2<D>::UnregisterPropertyChangedCallback(winrt::Windows::UI::Xaml::DependencyProperty const& dp, int64_t token) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObject2)->UnregisterPropertyChangedCallback(*(void**)(&dp), token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObjectCollection) consume_Windows_UI_Xaml_IDependencyObjectCollectionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObjectCollectionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::DependencyObjectCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_IDependencyObjectFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyObjectFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IDependencyProperty<D>::GetMetadata(winrt::Windows::UI::Xaml::Interop::TypeName const& forType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyProperty)->GetMetadata(impl::bind_in(forType), &result));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IDependencyPropertyChangedEventArgs<D>::Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs)->get_Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDependencyPropertyChangedEventArgs<D>::OldValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs)->get_OldValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDependencyPropertyChangedEventArgs<D>::NewValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs)->get_NewValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IDependencyPropertyStatics<D>::UnsetValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyPropertyStatics)->get_UnsetValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IDependencyPropertyStatics<D>::Register(param::hstring const& name, winrt::Windows::UI::Xaml::Interop::TypeName const& propertyType, winrt::Windows::UI::Xaml::Interop::TypeName const& ownerType, winrt::Windows::UI::Xaml::PropertyMetadata const& typeMetadata) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyPropertyStatics)->Register(*(void**)(&name), impl::bind_in(propertyType), impl::bind_in(ownerType), *(void**)(&typeMetadata), &result));
        return winrt::Windows::UI::Xaml::DependencyProperty{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IDependencyPropertyStatics<D>::RegisterAttached(param::hstring const& name, winrt::Windows::UI::Xaml::Interop::TypeName const& propertyType, winrt::Windows::UI::Xaml::Interop::TypeName const& ownerType, winrt::Windows::UI::Xaml::PropertyMetadata const& defaultMetadata) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDependencyPropertyStatics)->RegisterAttached(*(void**)(&name), impl::bind_in(propertyType), impl::bind_in(ownerType), *(void**)(&defaultMetadata), &result));
        return winrt::Windows::UI::Xaml::DependencyProperty{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Xaml_IDispatcherTimer<D>::Interval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->get_Interval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDispatcherTimer<D>::Interval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->put_Interval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDispatcherTimer<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->add_Tick(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick_revoker consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Tick_revoker>(this, Tick(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->remove_Tick(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDispatcherTimer<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDispatcherTimer<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimer)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DispatcherTimer) consume_Windows_UI_Xaml_IDispatcherTimerFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDispatcherTimerFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::DispatcherTimer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDragEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackage) consume_Windows_UI_Xaml_IDragEventArgs<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs)->get_Data(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragEventArgs<D>::Data(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_IDragEventArgs<D>::GetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs)->GetPosition(*(void**)(&relativeTo), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_UI_Xaml_IDragEventArgs2<D>::DataView() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs2)->get_DataView(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DragUIOverride) consume_Windows_UI_Xaml_IDragEventArgs2<D>::DragUIOverride() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs2)->get_DragUIOverride(&value));
        return winrt::Windows::UI::Xaml::DragUIOverride{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers) consume_Windows_UI_Xaml_IDragEventArgs2<D>::Modifiers() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs2)->get_Modifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_UI_Xaml_IDragEventArgs2<D>::AcceptedOperation() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs2)->get_AcceptedOperation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragEventArgs2<D>::AcceptedOperation(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs2)->put_AcceptedOperation(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DragOperationDeferral) consume_Windows_UI_Xaml_IDragEventArgs2<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs2)->GetDeferral(&result));
        return winrt::Windows::UI::Xaml::DragOperationDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_UI_Xaml_IDragEventArgs3<D>::AllowedOperations() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragEventArgs3)->get_AllowedOperations(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragOperationDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragOperationDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackage) consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs)->get_Data(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DragUI) consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::DragUI() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs)->get_DragUI(&value));
        return winrt::Windows::UI::Xaml::DragUI{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DragOperationDeferral) consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs)->GetDeferral(&result));
        return winrt::Windows::UI::Xaml::DragOperationDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::GetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs)->GetPosition(*(void**)(&relativeTo), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_UI_Xaml_IDragStartingEventArgs2<D>::AllowedOperations() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs2)->get_AllowedOperations(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragStartingEventArgs2<D>::AllowedOperations(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragStartingEventArgs2)->put_AllowedOperations(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromBitmapImage(winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUI)->SetContentFromBitmapImage(*(void**)(&bitmapImage)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromBitmapImage(winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage, winrt::Windows::Foundation::Point const& anchorPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUI)->SetContentFromBitmapImageWithAnchorPoint(*(void**)(&bitmapImage), impl::bind_in(anchorPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUI)->SetContentFromSoftwareBitmap(*(void**)(&softwareBitmap)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap, winrt::Windows::Foundation::Point const& anchorPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUI)->SetContentFromSoftwareBitmapWithAnchorPoint(*(void**)(&softwareBitmap), impl::bind_in(anchorPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromDataPackage() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUI)->SetContentFromDataPackage());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IDragUIOverride<D>::Caption() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->get_Caption(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::Caption(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->put_Caption(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDragUIOverride<D>::IsContentVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->get_IsContentVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::IsContentVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->put_IsContentVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDragUIOverride<D>::IsCaptionVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->get_IsCaptionVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::IsCaptionVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->put_IsCaptionVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDragUIOverride<D>::IsGlyphVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->get_IsGlyphVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::IsGlyphVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->put_IsGlyphVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromBitmapImage(winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->SetContentFromBitmapImage(*(void**)(&bitmapImage)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromBitmapImage(winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage, winrt::Windows::Foundation::Point const& anchorPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->SetContentFromBitmapImageWithAnchorPoint(*(void**)(&bitmapImage), impl::bind_in(anchorPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->SetContentFromSoftwareBitmap(*(void**)(&softwareBitmap)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap, winrt::Windows::Foundation::Point const& anchorPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDragUIOverride)->SetContentFromSoftwareBitmapWithAnchorPoint(*(void**)(&softwareBitmap), impl::bind_in(anchorPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_UI_Xaml_IDropCompletedEventArgs<D>::DropResult() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDropCompletedEventArgs)->get_DropResult(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Automatic() const
    {
        winrt::Windows::UI::Xaml::Duration value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->get_Automatic(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Forever() const
    {
        winrt::Windows::UI::Xaml::Duration value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->get_Forever(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Compare(winrt::Windows::UI::Xaml::Duration const& duration1, winrt::Windows::UI::Xaml::Duration const& duration2) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->Compare(impl::bind_in(duration1), impl::bind_in(duration2), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::FromTimeSpan(winrt::Windows::Foundation::TimeSpan const& timeSpan) const
    {
        winrt::Windows::UI::Xaml::Duration result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->FromTimeSpan(impl::bind_in(timeSpan), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::GetHasTimeSpan(winrt::Windows::UI::Xaml::Duration const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->GetHasTimeSpan(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Add(winrt::Windows::UI::Xaml::Duration const& target, winrt::Windows::UI::Xaml::Duration const& duration) const
    {
        winrt::Windows::UI::Xaml::Duration result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->Add(impl::bind_in(target), impl::bind_in(duration), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Equals(winrt::Windows::UI::Xaml::Duration const& target, winrt::Windows::UI::Xaml::Duration const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->Equals(impl::bind_in(target), impl::bind_in(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Subtract(winrt::Windows::UI::Xaml::Duration const& target, winrt::Windows::UI::Xaml::Duration const& duration) const
    {
        winrt::Windows::UI::Xaml::Duration result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IDurationHelperStatics)->Subtract(impl::bind_in(target), impl::bind_in(duration), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::EffectiveViewport() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_EffectiveViewport(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::MaxViewport() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_MaxViewport(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::BringIntoViewDistanceX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_BringIntoViewDistanceX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::BringIntoViewDistanceY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_BringIntoViewDistanceY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IElementFactory<D>::GetElement(winrt::Windows::UI::Xaml::ElementFactoryGetArgs const& args) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactory)->GetElement(*(void**)(&args), &result));
        return winrt::Windows::UI::Xaml::UIElement{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementFactory<D>::RecycleElement(winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactory)->RecycleElement(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryGetArgs)->get_Data(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Data(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryGetArgs)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Parent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryGetArgs)->get_Parent(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Parent(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryGetArgs)->put_Parent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementFactoryGetArgs) consume_Windows_UI_Xaml_IElementFactoryGetArgsFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryGetArgsFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::ElementFactoryGetArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Element() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs)->get_Element(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Element(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs)->put_Element(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Parent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs)->get_Parent(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Parent(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs)->put_Parent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs) consume_Windows_UI_Xaml_IElementFactoryRecycleArgsFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementFactoryRecycleArgsFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::Volume() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics)->get_Volume(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::Volume(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics)->put_Volume(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSoundPlayerState) consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::State() const
    {
        winrt::Windows::UI::Xaml::ElementSoundPlayerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::State(winrt::Windows::UI::Xaml::ElementSoundPlayerState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics)->put_State(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::Play(winrt::Windows::UI::Xaml::ElementSoundKind const& sound) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics)->Play(static_cast<int32_t>(sound)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSpatialAudioMode) consume_Windows_UI_Xaml_IElementSoundPlayerStatics2<D>::SpatialAudioMode() const
    {
        winrt::Windows::UI::Xaml::ElementSpatialAudioMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2)->get_SpatialAudioMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IElementSoundPlayerStatics2<D>::SpatialAudioMode(winrt::Windows::UI::Xaml::ElementSpatialAudioMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2)->put_SpatialAudioMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IEventTrigger<D>::RoutedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEventTrigger)->get_RoutedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IEventTrigger<D>::RoutedEvent(winrt::Windows::UI::Xaml::RoutedEvent const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEventTrigger)->put_RoutedEvent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TriggerActionCollection) consume_Windows_UI_Xaml_IEventTrigger<D>::Actions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IEventTrigger)->get_Actions(&value));
        return winrt::Windows::UI::Xaml::TriggerActionCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IExceptionRoutedEventArgs<D>::ErrorMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IExceptionRoutedEventArgs)->get_ErrorMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TriggerCollection) consume_Windows_UI_Xaml_IFrameworkElement<D>::Triggers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Triggers(&value));
        return winrt::Windows::UI::Xaml::TriggerCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ResourceDictionary) consume_Windows_UI_Xaml_IFrameworkElement<D>::Resources() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Resources(&value));
        return winrt::Windows::UI::Xaml::ResourceDictionary{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Resources(winrt::Windows::UI::Xaml::ResourceDictionary const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Resources(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IFrameworkElement<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Tag(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Tag(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IFrameworkElement<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::ActualWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_ActualWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::ActualHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_ActualHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::Width() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Width(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Width(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::Height() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Height(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Height(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::MinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_MinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::MinWidth(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_MinWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_MaxWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxWidth(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_MaxWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::MinHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_MinHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::MinHeight(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_MinHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_MaxHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxHeight(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_MaxHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::HorizontalAlignment) consume_Windows_UI_Xaml_IFrameworkElement<D>::HorizontalAlignment() const
    {
        winrt::Windows::UI::Xaml::HorizontalAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_HorizontalAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::HorizontalAlignment(winrt::Windows::UI::Xaml::HorizontalAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_HorizontalAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VerticalAlignment) consume_Windows_UI_Xaml_IFrameworkElement<D>::VerticalAlignment() const
    {
        winrt::Windows::UI::Xaml::VerticalAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_VerticalAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::VerticalAlignment(winrt::Windows::UI::Xaml::VerticalAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_VerticalAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_IFrameworkElement<D>::Margin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Margin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Margin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Margin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IFrameworkElement<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Xaml_IFrameworkElement<D>::BaseUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_BaseUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IFrameworkElement<D>::DataContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_DataContext(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::DataContext(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_DataContext(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Style) consume_Windows_UI_Xaml_IFrameworkElement<D>::Style() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Style(&value));
        return winrt::Windows::UI::Xaml::Style{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Style(winrt::Windows::UI::Xaml::Style const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_Style(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_IFrameworkElement<D>::Parent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_Parent(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FlowDirection) consume_Windows_UI_Xaml_IFrameworkElement<D>::FlowDirection() const
    {
        winrt::Windows::UI::Xaml::FlowDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->get_FlowDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::FlowDirection(winrt::Windows::UI::Xaml::FlowDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->put_FlowDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->add_Loaded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Loaded_revoker>(this, Loaded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->remove_Loaded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->add_Unloaded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Unloaded_revoker>(this, Unloaded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->remove_Unloaded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged(winrt::Windows::UI::Xaml::SizeChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->add_SizeChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged(auto_revoke_t, winrt::Windows::UI::Xaml::SizeChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->remove_SizeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->add_LayoutUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, LayoutUpdated_revoker>(this, LayoutUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->remove_LayoutUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IFrameworkElement<D>::FindName(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->FindName(*(void**)(&name), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement<D>::SetBinding(winrt::Windows::UI::Xaml::DependencyProperty const& dp, winrt::Windows::UI::Xaml::Data::BindingBase const& binding) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement)->SetBinding(*(void**)(&dp), *(void**)(&binding)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementTheme) consume_Windows_UI_Xaml_IFrameworkElement2<D>::RequestedTheme() const
    {
        winrt::Windows::UI::Xaml::ElementTheme value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement2)->get_RequestedTheme(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement2<D>::RequestedTheme(winrt::Windows::UI::Xaml::ElementTheme const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement2)->put_RequestedTheme(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::DataContextChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement2)->add_DataContextChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::DataContextChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DataContextChanged_revoker>(this, DataContextChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement2)->remove_DataContextChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::BindingExpression) consume_Windows_UI_Xaml_IFrameworkElement2<D>::GetBindingExpression(winrt::Windows::UI::Xaml::DependencyProperty const& dp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement2)->GetBindingExpression(*(void**)(&dp), &result));
        return winrt::Windows::UI::Xaml::Data::BindingExpression{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement3)->add_Loading(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading_revoker consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Loading_revoker>(this, Loading(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement3)->remove_Loading(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusOnInteraction() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_AllowFocusOnInteraction(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusOnInteraction(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_AllowFocusOnInteraction(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualMargin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualMargin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryThickness() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualSecondaryThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryThickness(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualSecondaryThickness(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryThickness() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualPrimaryThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryThickness(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualPrimaryThickness(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualSecondaryBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualSecondaryBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualPrimaryBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualPrimaryBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusWhenDisabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->get_AllowFocusWhenDisabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusWhenDisabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement4)->put_AllowFocusWhenDisabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementTheme) consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualTheme() const
    {
        winrt::Windows::UI::Xaml::ElementTheme value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement6)->get_ActualTheme(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement6)->add_ActualThemeChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ActualThemeChanged_revoker>(this, ActualThemeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement6)->remove_ActualThemeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IFrameworkElement7<D>::IsLoaded() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement7)->get_IsLoaded(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement7)->add_EffectiveViewportChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, EffectiveViewportChanged_revoker>(this, EffectiveViewportChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElement7)->remove_EffectiveViewportChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FrameworkElement) consume_Windows_UI_Xaml_IFrameworkElementFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::FrameworkElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_IFrameworkElementOverrides<D>::MeasureOverride(winrt::Windows::Foundation::Size const& availableSize) const
    {
        winrt::Windows::Foundation::Size result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementOverrides)->MeasureOverride(impl::bind_in(availableSize), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_IFrameworkElementOverrides<D>::ArrangeOverride(winrt::Windows::Foundation::Size const& finalSize) const
    {
        winrt::Windows::Foundation::Size result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementOverrides)->ArrangeOverride(impl::bind_in(finalSize), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElementOverrides<D>::OnApplyTemplate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementOverrides)->OnApplyTemplate());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IFrameworkElementOverrides2<D>::GoToElementStateCore(param::hstring const& stateName, bool useTransitions) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementOverrides2)->GoToElementStateCore(*(void**)(&stateName), useTransitions, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElementProtected7<D>::InvalidateViewport() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementProtected7)->InvalidateViewport());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::TagProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_TagProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::LanguageProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_LanguageProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::ActualWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_ActualWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::ActualHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_ActualHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::WidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_WidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::HeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_HeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MinWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_MinWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MaxWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_MaxWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MinHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_MinHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MaxHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_MaxHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::HorizontalAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_HorizontalAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::VerticalAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_VerticalAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_MarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::NameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_NameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::DataContextProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_DataContextProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::StyleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_StyleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::FlowDirectionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics)->get_FlowDirectionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics2<D>::RequestedThemeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics2)->get_RequestedThemeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::AllowFocusOnInteractionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_AllowFocusOnInteractionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualMarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualMarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualSecondaryThicknessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualSecondaryThicknessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualPrimaryThicknessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualPrimaryThicknessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualSecondaryBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualSecondaryBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualPrimaryBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualPrimaryBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::AllowFocusWhenDisabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics4)->get_AllowFocusWhenDisabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IFrameworkElementStatics5<D>::DeferTree(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics5)->DeferTree(*(void**)(&element)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IFrameworkElementStatics6<D>::ActualThemeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkElementStatics6)->get_ActualThemeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FrameworkTemplate) consume_Windows_UI_Xaml_IFrameworkTemplateFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IFrameworkTemplateFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::FrameworkTemplate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::GridLength) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::Auto() const
    {
        winrt::Windows::UI::Xaml::GridLength value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->get_Auto(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::GridLength) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::FromPixels(double pixels) const
    {
        winrt::Windows::UI::Xaml::GridLength result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->FromPixels(pixels, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::GridLength) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::FromValueAndType(double value, winrt::Windows::UI::Xaml::GridUnitType const& type) const
    {
        winrt::Windows::UI::Xaml::GridLength result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->FromValueAndType(value, static_cast<int32_t>(type), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::GetIsAbsolute(winrt::Windows::UI::Xaml::GridLength const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->GetIsAbsolute(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::GetIsAuto(winrt::Windows::UI::Xaml::GridLength const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->GetIsAuto(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::GetIsStar(winrt::Windows::UI::Xaml::GridLength const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->GetIsStar(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::Equals(winrt::Windows::UI::Xaml::GridLength const& target, winrt::Windows::UI::Xaml::GridLength const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IGridLengthHelperStatics)->Equals(impl::bind_in(target), impl::bind_in(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IMediaFailedRoutedEventArgs<D>::ErrorTrace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IMediaFailedRoutedEventArgs)->get_ErrorTrace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_IPointHelperStatics<D>::FromCoordinates(float x, float y) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPointHelperStatics)->FromCoordinates(x, y, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IPropertyMetadata<D>::DefaultValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadata)->get_DefaultValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::CreateDefaultValueCallback) consume_Windows_UI_Xaml_IPropertyMetadata<D>::CreateDefaultValueCallback() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadata)->get_CreateDefaultValueCallback(&value));
        return winrt::Windows::UI::Xaml::CreateDefaultValueCallback{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IPropertyMetadataFactory<D>::CreateInstanceWithDefaultValue(winrt::Windows::Foundation::IInspectable const& defaultValue, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadataFactory)->CreateInstanceWithDefaultValue(*(void**)(&defaultValue), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IPropertyMetadataFactory<D>::CreateInstanceWithDefaultValueAndCallback(winrt::Windows::Foundation::IInspectable const& defaultValue, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadataFactory)->CreateInstanceWithDefaultValueAndCallback(*(void**)(&defaultValue), *(void**)(&propertyChangedCallback), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(winrt::Windows::Foundation::IInspectable const& defaultValue) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithDefaultValue(*(void**)(&defaultValue), &result));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(winrt::Windows::Foundation::IInspectable const& defaultValue, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithDefaultValueAndCallback(*(void**)(&defaultValue), *(void**)(&propertyChangedCallback), &result));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(winrt::Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithFactory(*(void**)(&createDefaultValueCallback), &result));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyMetadata) consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(winrt::Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithFactoryAndCallback(*(void**)(&createDefaultValueCallback), *(void**)(&propertyChangedCallback), &result));
        return winrt::Windows::UI::Xaml::PropertyMetadata{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IPropertyPath<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyPath)->get_Path(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyPath) consume_Windows_UI_Xaml_IPropertyPathFactory<D>::CreateInstance(param::hstring const& path) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IPropertyPathFactory)->CreateInstance(*(void**)(&path), &value));
        return winrt::Windows::UI::Xaml::PropertyPath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::Empty() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->get_Empty(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::FromCoordinatesAndDimensions(float x, float y, float width, float height) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->FromCoordinatesAndDimensions(x, y, width, height, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::FromPoints(winrt::Windows::Foundation::Point const& point1, winrt::Windows::Foundation::Point const& point2) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->FromPoints(impl::bind_in(point1), impl::bind_in(point2), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::FromLocationAndSize(winrt::Windows::Foundation::Point const& location, winrt::Windows::Foundation::Size const& size) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->FromLocationAndSize(impl::bind_in(location), impl::bind_in(size), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetIsEmpty(winrt::Windows::Foundation::Rect const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->GetIsEmpty(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetBottom(winrt::Windows::Foundation::Rect const& target) const
    {
        float result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->GetBottom(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetLeft(winrt::Windows::Foundation::Rect const& target) const
    {
        float result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->GetLeft(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetRight(winrt::Windows::Foundation::Rect const& target) const
    {
        float result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->GetRight(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetTop(winrt::Windows::Foundation::Rect const& target) const
    {
        float result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->GetTop(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IRectHelperStatics<D>::Contains(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Point const& point) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->Contains(impl::bind_in(target), impl::bind_in(point), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IRectHelperStatics<D>::Equals(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Rect const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->Equals(impl::bind_in(target), impl::bind_in(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::Intersect(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Rect const& rect) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->Intersect(impl::bind_in(target), impl::bind_in(rect), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::Union(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Point const& point) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->UnionWithPoint(impl::bind_in(target), impl::bind_in(point), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IRectHelperStatics<D>::Union(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Rect const& rect) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRectHelperStatics)->UnionWithRect(impl::bind_in(target), impl::bind_in(rect), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Xaml_IResourceDictionary<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IResourceDictionary)->get_Source(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IResourceDictionary<D>::Source(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IResourceDictionary)->put_Source(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::ResourceDictionary>) consume_Windows_UI_Xaml_IResourceDictionary<D>::MergedDictionaries() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IResourceDictionary)->get_MergedDictionaries(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::ResourceDictionary>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>) consume_Windows_UI_Xaml_IResourceDictionary<D>::ThemeDictionaries() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IResourceDictionary)->get_ThemeDictionaries(&value));
        return winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ResourceDictionary) consume_Windows_UI_Xaml_IResourceDictionaryFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IResourceDictionaryFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::ResourceDictionary{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_IRoutedEventArgs<D>::OriginalSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRoutedEventArgs)->get_OriginalSource(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEventArgs) consume_Windows_UI_Xaml_IRoutedEventArgsFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IRoutedEventArgsFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::RoutedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Xaml_IScalarTransition<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IScalarTransition)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IScalarTransition<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IScalarTransition)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ScalarTransition) consume_Windows_UI_Xaml_IScalarTransitionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IScalarTransitionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::ScalarTransition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_ISetter<D>::Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetter)->get_Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_ISetter<D>::Property(winrt::Windows::UI::Xaml::DependencyProperty const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetter)->put_Property(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_ISetter<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetter)->get_Value(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_ISetter<D>::Value(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetter)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TargetPropertyPath) consume_Windows_UI_Xaml_ISetter2<D>::Target() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetter2)->get_Target(&value));
        return winrt::Windows::UI::Xaml::TargetPropertyPath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_ISetter2<D>::Target(winrt::Windows::UI::Xaml::TargetPropertyPath const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetter2)->put_Target(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_ISetterBase<D>::IsSealed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetterBase)->get_IsSealed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_ISetterBaseCollection<D>::IsSealed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetterBaseCollection)->get_IsSealed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Setter) consume_Windows_UI_Xaml_ISetterFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::DependencyProperty const& targetProperty, winrt::Windows::Foundation::IInspectable const& value) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISetterFactory)->CreateInstance(*(void**)(&targetProperty), *(void**)(&value), &instance));
        return winrt::Windows::UI::Xaml::Setter{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_ISizeChangedEventArgs<D>::PreviousSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISizeChangedEventArgs)->get_PreviousSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_ISizeChangedEventArgs<D>::NewSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISizeChangedEventArgs)->get_NewSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_ISizeHelperStatics<D>::Empty() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISizeHelperStatics)->get_Empty(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_ISizeHelperStatics<D>::FromDimensions(float width, float height) const
    {
        winrt::Windows::Foundation::Size result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISizeHelperStatics)->FromDimensions(width, height, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_ISizeHelperStatics<D>::GetIsEmpty(winrt::Windows::Foundation::Size const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISizeHelperStatics)->GetIsEmpty(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_ISizeHelperStatics<D>::Equals(winrt::Windows::Foundation::Size const& target, winrt::Windows::Foundation::Size const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ISizeHelperStatics)->Equals(impl::bind_in(target), impl::bind_in(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IStateTrigger<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStateTrigger)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IStateTrigger<D>::IsActive(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStateTrigger)->put_IsActive(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::StateTriggerBase) consume_Windows_UI_Xaml_IStateTriggerBaseFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStateTriggerBaseFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::StateTriggerBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IStateTriggerBaseProtected<D>::SetActive(bool IsActive) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStateTriggerBaseProtected)->SetActive(IsActive));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IStateTriggerStatics<D>::IsActiveProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStateTriggerStatics)->get_IsActiveProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IStyle<D>::IsSealed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->get_IsSealed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::SetterBaseCollection) consume_Windows_UI_Xaml_IStyle<D>::Setters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->get_Setters(&value));
        return winrt::Windows::UI::Xaml::SetterBaseCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Interop::TypeName) consume_Windows_UI_Xaml_IStyle<D>::TargetType() const
    {
        winrt::Windows::UI::Xaml::Interop::TypeName value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->get_TargetType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IStyle<D>::TargetType(winrt::Windows::UI::Xaml::Interop::TypeName const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->put_TargetType(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Style) consume_Windows_UI_Xaml_IStyle<D>::BasedOn() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->get_BasedOn(&value));
        return winrt::Windows::UI::Xaml::Style{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IStyle<D>::BasedOn(winrt::Windows::UI::Xaml::Style const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->put_BasedOn(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IStyle<D>::Seal() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyle)->Seal());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Style) consume_Windows_UI_Xaml_IStyleFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::Interop::TypeName const& targetType) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IStyleFactory)->CreateInstance(impl::bind_in(targetType), &value));
        return winrt::Windows::UI::Xaml::Style{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyPath) consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ITargetPropertyPath)->get_Path(&value));
        return winrt::Windows::UI::Xaml::PropertyPath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Path(winrt::Windows::UI::Xaml::PropertyPath const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ITargetPropertyPath)->put_Path(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Target() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ITargetPropertyPath)->get_Target(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Target(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ITargetPropertyPath)->put_Target(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TargetPropertyPath) consume_Windows_UI_Xaml_ITargetPropertyPathFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::DependencyProperty const& targetProperty) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::ITargetPropertyPathFactory)->CreateInstance(*(void**)(&targetProperty), &value));
        return winrt::Windows::UI::Xaml::TargetPropertyPath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_IThicknessHelperStatics<D>::FromLengths(double left, double top, double right, double bottom) const
    {
        winrt::Windows::UI::Xaml::Thickness result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IThicknessHelperStatics)->FromLengths(left, top, right, bottom, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_IThicknessHelperStatics<D>::FromUniformLength(double uniformLength) const
    {
        winrt::Windows::UI::Xaml::Thickness result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IThicknessHelperStatics)->FromUniformLength(uniformLength, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_IUIElement<D>::DesiredSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_DesiredSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::AllowDrop() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_AllowDrop(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::AllowDrop(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_AllowDrop(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IUIElement<D>::Opacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_Opacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Opacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_Opacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::RectangleGeometry) consume_Windows_UI_Xaml_IUIElement<D>::Clip() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_Clip(&value));
        return winrt::Windows::UI::Xaml::Media::RectangleGeometry{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Clip(winrt::Windows::UI::Xaml::Media::RectangleGeometry const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_Clip(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Transform) consume_Windows_UI_Xaml_IUIElement<D>::RenderTransform() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_RenderTransform(&value));
        return winrt::Windows::UI::Xaml::Media::Transform{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::RenderTransform(winrt::Windows::UI::Xaml::Media::Transform const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_RenderTransform(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Projection) consume_Windows_UI_Xaml_IUIElement<D>::Projection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_Projection(&value));
        return winrt::Windows::UI::Xaml::Media::Projection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Projection(winrt::Windows::UI::Xaml::Media::Projection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_Projection(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_IUIElement<D>::RenderTransformOrigin() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_RenderTransformOrigin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::RenderTransformOrigin(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_RenderTransformOrigin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::IsHitTestVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_IsHitTestVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::IsHitTestVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_IsHitTestVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Visibility) consume_Windows_UI_Xaml_IUIElement<D>::Visibility() const
    {
        winrt::Windows::UI::Xaml::Visibility value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_Visibility(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Visibility(winrt::Windows::UI::Xaml::Visibility const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_Visibility(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_IUIElement<D>::RenderSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_RenderSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::UseLayoutRounding() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_UseLayoutRounding(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::UseLayoutRounding(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_UseLayoutRounding(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection) consume_Windows_UI_Xaml_IUIElement<D>::Transitions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_Transitions(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Transitions(winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_Transitions(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::CacheMode) consume_Windows_UI_Xaml_IUIElement<D>::CacheMode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_CacheMode(&value));
        return winrt::Windows::UI::Xaml::Media::CacheMode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::CacheMode(winrt::Windows::UI::Xaml::Media::CacheMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_CacheMode(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::IsTapEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_IsTapEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::IsTapEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_IsTapEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::IsDoubleTapEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_IsDoubleTapEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::IsDoubleTapEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_IsDoubleTapEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::IsRightTapEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_IsRightTapEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::IsRightTapEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_IsRightTapEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::IsHoldingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_IsHoldingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::IsHoldingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_IsHoldingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ManipulationModes) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationMode() const
    {
        winrt::Windows::UI::Xaml::Input::ManipulationModes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_ManipulationMode(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationMode(winrt::Windows::UI::Xaml::Input::ManipulationModes const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->put_ManipulationMode(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Input::Pointer>) consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptures() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->get_PointerCaptures(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Input::Pointer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::KeyUp(winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_KeyUp(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::KeyUp_revoker consume_Windows_UI_Xaml_IUIElement<D>::KeyUp(auto_revoke_t, winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::KeyUp(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_KeyUp(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::KeyDown(winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_KeyDown(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::KeyDown_revoker consume_Windows_UI_Xaml_IUIElement<D>::KeyDown(auto_revoke_t, winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::KeyDown(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_KeyDown(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::GotFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_GotFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::GotFocus_revoker consume_Windows_UI_Xaml_IUIElement<D>::GotFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::GotFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_GotFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::LostFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_LostFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::LostFocus_revoker consume_Windows_UI_Xaml_IUIElement<D>::LostFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::LostFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_LostFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::DragEnter(winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_DragEnter(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DragEnter_revoker consume_Windows_UI_Xaml_IUIElement<D>::DragEnter(auto_revoke_t, winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DragEnter_revoker>(this, DragEnter(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::DragEnter(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_DragEnter(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::DragLeave(winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_DragLeave(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DragLeave_revoker consume_Windows_UI_Xaml_IUIElement<D>::DragLeave(auto_revoke_t, winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DragLeave_revoker>(this, DragLeave(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::DragLeave(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_DragLeave(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::DragOver(winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_DragOver(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DragOver_revoker consume_Windows_UI_Xaml_IUIElement<D>::DragOver(auto_revoke_t, winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DragOver_revoker>(this, DragOver(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::DragOver(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_DragOver(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::Drop(winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_Drop(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::Drop_revoker consume_Windows_UI_Xaml_IUIElement<D>::Drop(auto_revoke_t, winrt::Windows::UI::Xaml::DragEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Drop_revoker>(this, Drop(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Drop(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_Drop(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerPressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerPressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerMoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerMoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerReleased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerReleased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerEntered(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerEntered(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerExited(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerExited(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerExited_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerExited(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerExited(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerExited(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerCaptureLost(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerCaptureLost_revoker>(this, PointerCaptureLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerCaptureLost(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerCanceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerCanceled_revoker>(this, PointerCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerCanceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged(winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_PointerWheelChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged(auto_revoke_t, winrt::Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PointerWheelChanged_revoker>(this, PointerWheelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_PointerWheelChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::Tapped(winrt::Windows::UI::Xaml::Input::TappedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_Tapped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::Tapped_revoker consume_Windows_UI_Xaml_IUIElement<D>::Tapped(auto_revoke_t, winrt::Windows::UI::Xaml::Input::TappedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Tapped_revoker>(this, Tapped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Tapped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_Tapped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped(winrt::Windows::UI::Xaml::Input::DoubleTappedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_DoubleTapped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped_revoker consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped(auto_revoke_t, winrt::Windows::UI::Xaml::Input::DoubleTappedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DoubleTapped_revoker>(this, DoubleTapped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_DoubleTapped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::Holding(winrt::Windows::UI::Xaml::Input::HoldingEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_Holding(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::Holding_revoker consume_Windows_UI_Xaml_IUIElement<D>::Holding(auto_revoke_t, winrt::Windows::UI::Xaml::Input::HoldingEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Holding_revoker>(this, Holding(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Holding(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_Holding(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::RightTapped(winrt::Windows::UI::Xaml::Input::RightTappedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_RightTapped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::RightTapped_revoker consume_Windows_UI_Xaml_IUIElement<D>::RightTapped(auto_revoke_t, winrt::Windows::UI::Xaml::Input::RightTappedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, RightTapped_revoker>(this, RightTapped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::RightTapped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_RightTapped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting(winrt::Windows::UI::Xaml::Input::ManipulationStartingEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_ManipulationStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting(auto_revoke_t, winrt::Windows::UI::Xaml::Input::ManipulationStartingEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationStarting_revoker>(this, ManipulationStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_ManipulationStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting(winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_ManipulationInertiaStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting(auto_revoke_t, winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationInertiaStarting_revoker>(this, ManipulationInertiaStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_ManipulationInertiaStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted(winrt::Windows::UI::Xaml::Input::ManipulationStartedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_ManipulationStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted(auto_revoke_t, winrt::Windows::UI::Xaml::Input::ManipulationStartedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationStarted_revoker>(this, ManipulationStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_ManipulationStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta(winrt::Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_ManipulationDelta(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta(auto_revoke_t, winrt::Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationDelta_revoker>(this, ManipulationDelta(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_ManipulationDelta(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted(winrt::Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->add_ManipulationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted(auto_revoke_t, winrt::Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationCompleted_revoker>(this, ManipulationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->remove_ManipulationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Measure(winrt::Windows::Foundation::Size const& availableSize) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->Measure(impl::bind_in(availableSize)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::Arrange(winrt::Windows::Foundation::Rect const& finalRect) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->Arrange(impl::bind_in(finalRect)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement<D>::CapturePointer(winrt::Windows::UI::Xaml::Input::Pointer const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->CapturePointer(*(void**)(&value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ReleasePointerCapture(winrt::Windows::UI::Xaml::Input::Pointer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->ReleasePointerCapture(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::ReleasePointerCaptures() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->ReleasePointerCaptures());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::AddHandler(winrt::Windows::UI::Xaml::RoutedEvent const& routedEvent, winrt::Windows::Foundation::IInspectable const& handler, bool handledEventsToo) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->AddHandler(*(void**)(&routedEvent), *(void**)(&handler), handledEventsToo));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::RemoveHandler(winrt::Windows::UI::Xaml::RoutedEvent const& routedEvent, winrt::Windows::Foundation::IInspectable const& handler) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->RemoveHandler(*(void**)(&routedEvent), *(void**)(&handler)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::GeneralTransform) consume_Windows_UI_Xaml_IUIElement<D>::TransformToVisual(winrt::Windows::UI::Xaml::UIElement const& visual) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->TransformToVisual(*(void**)(&visual), &result));
        return winrt::Windows::UI::Xaml::Media::GeneralTransform{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::InvalidateMeasure() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->InvalidateMeasure());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::InvalidateArrange() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->InvalidateArrange());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement<D>::UpdateLayout() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement)->UpdateLayout());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Xaml_IUIElement10<D>::ActualOffset() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->get_ActualOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float2) consume_Windows_UI_Xaml_IUIElement10<D>::ActualSize() const
    {
        winrt::Windows::Foundation::Numerics::float2 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->get_ActualSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::XamlRoot) consume_Windows_UI_Xaml_IUIElement10<D>::XamlRoot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->get_XamlRoot(&value));
        return winrt::Windows::UI::Xaml::XamlRoot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement10<D>::XamlRoot(winrt::Windows::UI::Xaml::XamlRoot const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->put_XamlRoot(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIContext) consume_Windows_UI_Xaml_IUIElement10<D>::UIContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->get_UIContext(&value));
        return winrt::Windows::UI::UIContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Shadow) consume_Windows_UI_Xaml_IUIElement10<D>::Shadow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->get_Shadow(&value));
        return winrt::Windows::UI::Xaml::Media::Shadow{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement10<D>::Shadow(winrt::Windows::UI::Xaml::Media::Shadow const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement10)->put_Shadow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::ElementCompositeMode) consume_Windows_UI_Xaml_IUIElement2<D>::CompositeMode() const
    {
        winrt::Windows::UI::Xaml::Media::ElementCompositeMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement2)->get_CompositeMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement2<D>::CompositeMode(winrt::Windows::UI::Xaml::Media::ElementCompositeMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement2)->put_CompositeMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement2<D>::CancelDirectManipulations() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement2)->CancelDirectManipulations(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Media3D::Transform3D) consume_Windows_UI_Xaml_IUIElement3<D>::Transform3D() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->get_Transform3D(&value));
        return winrt::Windows::UI::Xaml::Media::Media3D::Transform3D{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement3<D>::Transform3D(winrt::Windows::UI::Xaml::Media::Media3D::Transform3D const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->put_Transform3D(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement3<D>::CanDrag() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->get_CanDrag(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement3<D>::CanDrag(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->put_CanDrag(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DragStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->add_DragStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting_revoker consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DragStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DragStarting_revoker>(this, DragStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->remove_DragStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DropCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->add_DropCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted_revoker consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DropCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DropCompleted_revoker>(this, DropCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->remove_DropCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>) consume_Windows_UI_Xaml_IUIElement3<D>::StartDragAsync(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement3)->StartDragAsync(*(void**)(&pointerPoint), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase) consume_Windows_UI_Xaml_IUIElement4<D>::ContextFlyout() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->get_ContextFlyout(&value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::ContextFlyout(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->put_ContextFlyout(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement4<D>::ExitDisplayModeOnAccessKeyInvoked() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->get_ExitDisplayModeOnAccessKeyInvoked(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::ExitDisplayModeOnAccessKeyInvoked(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->put_ExitDisplayModeOnAccessKeyInvoked(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement4<D>::IsAccessKeyScope() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->get_IsAccessKeyScope(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::IsAccessKeyScope(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->put_IsAccessKeyScope(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyScopeOwner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->get_AccessKeyScopeOwner(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyScopeOwner(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->put_AccessKeyScopeOwner(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->get_AccessKey(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKey(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->put_AccessKey(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::ContextRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->add_ContextRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested_revoker consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::ContextRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ContextRequested_revoker>(this, ContextRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->remove_ContextRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::RoutedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->add_ContextCanceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled_revoker consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::RoutedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ContextCanceled_revoker>(this, ContextCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->remove_ContextCanceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->add_AccessKeyDisplayRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested_revoker consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessKeyDisplayRequested_revoker>(this, AccessKeyDisplayRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->remove_AccessKeyDisplayRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->add_AccessKeyDisplayDismissed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed_revoker consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessKeyDisplayDismissed_revoker>(this, AccessKeyDisplayDismissed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->remove_AccessKeyDisplayDismissed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->add_AccessKeyInvoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked_revoker consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessKeyInvoked_revoker>(this, AccessKeyInvoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement4)->remove_AccessKeyInvoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Media::XamlLight>) consume_Windows_UI_Xaml_IUIElement5<D>::Lights() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_Lights(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Media::XamlLight>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode) consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipPlacementMode() const
    {
        winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_KeyTipPlacementMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipPlacementMode(winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_KeyTipPlacementMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_KeyTipHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_KeyTipHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_KeyTipVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_KeyTipVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusKeyboardNavigation() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_XYFocusKeyboardNavigation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusKeyboardNavigation(winrt::Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_XYFocusKeyboardNavigation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusUpNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_XYFocusUpNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusUpNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_XYFocusUpNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusDownNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_XYFocusDownNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusDownNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_XYFocusDownNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusLeftNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_XYFocusLeftNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusLeftNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_XYFocusLeftNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusRightNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_XYFocusRightNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusRightNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_XYFocusRightNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementHighContrastAdjustment) consume_Windows_UI_Xaml_IUIElement5<D>::HighContrastAdjustment() const
    {
        winrt::Windows::UI::Xaml::ElementHighContrastAdjustment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_HighContrastAdjustment(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::HighContrastAdjustment(winrt::Windows::UI::Xaml::ElementHighContrastAdjustment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_HighContrastAdjustment(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyboardNavigationMode) consume_Windows_UI_Xaml_IUIElement5<D>::TabFocusNavigation() const
    {
        winrt::Windows::UI::Xaml::Input::KeyboardNavigationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->get_TabFocusNavigation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::TabFocusNavigation(winrt::Windows::UI::Xaml::Input::KeyboardNavigationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->put_TabFocusNavigation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->add_GettingFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus_revoker consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GettingFocus_revoker>(this, GettingFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->remove_GettingFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->add_LosingFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus_revoker consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LosingFocus_revoker>(this, LosingFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->remove_LosingFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->add_NoFocusCandidateFound(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound_revoker consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NoFocusCandidateFound_revoker>(this, NoFocusCandidateFound(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->remove_NoFocusCandidateFound(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::StartBringIntoView() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->StartBringIntoView());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement5<D>::StartBringIntoView(winrt::Windows::UI::Xaml::BringIntoViewOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement5)->StartBringIntoViewWithOptions(*(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>) consume_Windows_UI_Xaml_IUIElement7<D>::KeyboardAccelerators() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->get_KeyboardAccelerators(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->add_CharacterReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived_revoker consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CharacterReceived_revoker>(this, CharacterReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->remove_CharacterReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->add_ProcessKeyboardAccelerators(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators_revoker consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ProcessKeyboardAccelerators_revoker>(this, ProcessKeyboardAccelerators(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->remove_ProcessKeyboardAccelerators(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown(winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->add_PreviewKeyDown(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown_revoker consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown(auto_revoke_t, winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PreviewKeyDown_revoker>(this, PreviewKeyDown(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->remove_PreviewKeyDown(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp(winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->add_PreviewKeyUp(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp_revoker consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp(auto_revoke_t, winrt::Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PreviewKeyUp_revoker>(this, PreviewKeyUp(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->remove_PreviewKeyUp(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement7<D>::TryInvokeKeyboardAccelerator(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement7)->TryInvokeKeyboardAccelerator(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_IUIElement8<D>::KeyTipTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->get_KeyTipTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement8<D>::KeyTipTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->put_KeyTipTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->get_KeyboardAcceleratorPlacementTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->put_KeyboardAcceleratorPlacementTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode) consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementMode() const
    {
        winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->get_KeyboardAcceleratorPlacementMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementMode(winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->put_KeyboardAcceleratorPlacementMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->add_BringIntoViewRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested_revoker consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BringIntoViewRequested_revoker>(this, BringIntoViewRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement8)->remove_BringIntoViewRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElement9<D>::CanBeScrollAnchor() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_CanBeScrollAnchor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::CanBeScrollAnchor(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_CanBeScrollAnchor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ScalarTransition) consume_Windows_UI_Xaml_IUIElement9<D>::OpacityTransition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_OpacityTransition(&value));
        return winrt::Windows::UI::Xaml::ScalarTransition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::OpacityTransition(winrt::Windows::UI::Xaml::ScalarTransition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_OpacityTransition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Xaml_IUIElement9<D>::Translation() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_Translation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::Translation(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_Translation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Vector3Transition) consume_Windows_UI_Xaml_IUIElement9<D>::TranslationTransition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_TranslationTransition(&value));
        return winrt::Windows::UI::Xaml::Vector3Transition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::TranslationTransition(winrt::Windows::UI::Xaml::Vector3Transition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_TranslationTransition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Xaml_IUIElement9<D>::Rotation() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_Rotation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::Rotation(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_Rotation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ScalarTransition) consume_Windows_UI_Xaml_IUIElement9<D>::RotationTransition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_RotationTransition(&value));
        return winrt::Windows::UI::Xaml::ScalarTransition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::RotationTransition(winrt::Windows::UI::Xaml::ScalarTransition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_RotationTransition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Xaml_IUIElement9<D>::Scale() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_Scale(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::Scale(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_Scale(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Vector3Transition) consume_Windows_UI_Xaml_IUIElement9<D>::ScaleTransition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_ScaleTransition(&value));
        return winrt::Windows::UI::Xaml::Vector3Transition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::ScaleTransition(winrt::Windows::UI::Xaml::Vector3Transition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_ScaleTransition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float4x4) consume_Windows_UI_Xaml_IUIElement9<D>::TransformMatrix() const
    {
        winrt::Windows::Foundation::Numerics::float4x4 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_TransformMatrix(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::TransformMatrix(winrt::Windows::Foundation::Numerics::float4x4 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_TransformMatrix(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Xaml_IUIElement9<D>::CenterPoint() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_CenterPoint(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::CenterPoint(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_CenterPoint(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Xaml_IUIElement9<D>::RotationAxis() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->get_RotationAxis(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::RotationAxis(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->put_RotationAxis(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::StartAnimation(winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->StartAnimation(*(void**)(&animation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElement9<D>::StopAnimation(winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElement9)->StopAnimation(*(void**)(&animation)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_IUIElementOverrides<D>::OnCreateAutomationPeer() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides)->OnCreateAutomationPeer(&result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElementOverrides<D>::OnDisconnectVisualChildren() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides)->OnDisconnectVisualChildren());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Point>>) consume_Windows_UI_Xaml_IUIElementOverrides<D>::FindSubElementsForTouchTargeting(winrt::Windows::Foundation::Point const& point, winrt::Windows::Foundation::Rect const& boundingRect) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides)->FindSubElementsForTouchTargeting(impl::bind_in(point), impl::bind_in(boundingRect), &result));
        return winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Point>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::DependencyObject>) consume_Windows_UI_Xaml_IUIElementOverrides7<D>::GetChildrenInTabFocusOrder() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides7)->GetChildrenInTabFocusOrder(&result));
        return winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::DependencyObject>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElementOverrides7<D>::OnProcessKeyboardAccelerators(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides7)->OnProcessKeyboardAccelerators(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElementOverrides8<D>::OnKeyboardAcceleratorInvoked(winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides8)->OnKeyboardAcceleratorInvoked(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElementOverrides8<D>::OnBringIntoViewRequested(winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs const& e) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides8)->OnBringIntoViewRequested(*(void**)(&e)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElementOverrides9<D>::PopulatePropertyInfoOverride(param::hstring const& propertyName, winrt::Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementOverrides9)->PopulatePropertyInfoOverride(*(void**)(&propertyName), *(void**)(&animationPropertyInfo)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::KeyDownEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_KeyDownEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::KeyUpEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_KeyUpEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerEnteredEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerEnteredEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerPressedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerPressedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerMovedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerMovedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerReleasedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerReleasedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerExitedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerExitedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerCaptureLostEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerCaptureLostEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerCanceledEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerCanceledEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerWheelChangedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerWheelChangedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::TappedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_TappedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::DoubleTappedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_DoubleTappedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::HoldingEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_HoldingEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::RightTappedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_RightTappedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationStartingEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ManipulationStartingEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationInertiaStartingEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ManipulationInertiaStartingEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationStartedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ManipulationStartedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationDeltaEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ManipulationDeltaEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationCompletedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ManipulationCompletedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::DragEnterEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_DragEnterEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::DragLeaveEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_DragLeaveEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::DragOverEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_DragOverEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics<D>::DropEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_DropEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::AllowDropProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_AllowDropProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::OpacityProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_OpacityProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::ClipProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ClipProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::RenderTransformProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_RenderTransformProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::ProjectionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ProjectionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::RenderTransformOriginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_RenderTransformOriginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::IsHitTestVisibleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_IsHitTestVisibleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::VisibilityProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_VisibilityProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::UseLayoutRoundingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_UseLayoutRoundingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::TransitionsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_TransitionsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::CacheModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_CacheModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::IsTapEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_IsTapEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::IsDoubleTapEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_IsDoubleTapEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::IsRightTapEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_IsRightTapEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::IsHoldingEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_IsHoldingEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_ManipulationModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerCapturesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics)->get_PointerCapturesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics10<D>::ShadowProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics10)->get_ShadowProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics2<D>::CompositeModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics2)->get_CompositeModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics3<D>::Transform3DProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics3)->get_Transform3DProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics3<D>::CanDragProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics3)->get_CanDragProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUIElementStatics3<D>::TryStartDirectManipulation(winrt::Windows::UI::Xaml::Input::Pointer const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics3)->TryStartDirectManipulation(*(void**)(&value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics4<D>::ContextFlyoutProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics4)->get_ContextFlyoutProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics4<D>::ExitDisplayModeOnAccessKeyInvokedProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics4)->get_ExitDisplayModeOnAccessKeyInvokedProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics4<D>::IsAccessKeyScopeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics4)->get_IsAccessKeyScopeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics4<D>::AccessKeyScopeOwnerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics4)->get_AccessKeyScopeOwnerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics4<D>::AccessKeyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics4)->get_AccessKeyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::LightsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_LightsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::KeyTipPlacementModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_KeyTipPlacementModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::KeyTipHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_KeyTipHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::KeyTipVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_KeyTipVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusKeyboardNavigationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusKeyboardNavigationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusUpNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusUpNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusDownNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusDownNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusLeftNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusLeftNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusRightNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusRightNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::HighContrastAdjustmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_HighContrastAdjustmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics5<D>::TabFocusNavigationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics5)->get_TabFocusNavigationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics6<D>::GettingFocusEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics6)->get_GettingFocusEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics6<D>::LosingFocusEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics6)->get_LosingFocusEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics6<D>::NoFocusCandidateFoundEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics6)->get_NoFocusCandidateFoundEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics7<D>::PreviewKeyDownEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics7)->get_PreviewKeyDownEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics7<D>::CharacterReceivedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics7)->get_CharacterReceivedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics7<D>::PreviewKeyUpEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics7)->get_PreviewKeyUpEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics8<D>::BringIntoViewRequestedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics8)->get_BringIntoViewRequestedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::RoutedEvent) consume_Windows_UI_Xaml_IUIElementStatics8<D>::ContextRequestedEvent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics8)->get_ContextRequestedEvent(&value));
        return winrt::Windows::UI::Xaml::RoutedEvent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics8<D>::KeyTipTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics8)->get_KeyTipTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics8<D>::KeyboardAcceleratorPlacementTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics8)->get_KeyboardAcceleratorPlacementTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics8<D>::KeyboardAcceleratorPlacementModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics8)->get_KeyboardAcceleratorPlacementModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUIElementStatics8<D>::RegisterAsScrollPort(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics8)->RegisterAsScrollPort(*(void**)(&element)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IUIElementStatics9<D>::CanBeScrollAnchorProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementStatics9)->get_CanBeScrollAnchorProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElementWeakCollection) consume_Windows_UI_Xaml_IUIElementWeakCollectionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUIElementWeakCollectionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::UIElementWeakCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Exception() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs)->get_Exception(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Xaml_IVector3Transition<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVector3Transition)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVector3Transition<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVector3Transition)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Vector3TransitionComponents) consume_Windows_UI_Xaml_IVector3Transition<D>::Components() const
    {
        winrt::Windows::UI::Xaml::Vector3TransitionComponents value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVector3Transition)->get_Components(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVector3Transition<D>::Components(winrt::Windows::UI::Xaml::Vector3TransitionComponents const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVector3Transition)->put_Components(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Vector3Transition) consume_Windows_UI_Xaml_IVector3TransitionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVector3TransitionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Vector3Transition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IVisualState<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualState)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::Storyboard) consume_Windows_UI_Xaml_IVisualState<D>::Storyboard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualState)->get_Storyboard(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::Storyboard{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualState<D>::Storyboard(winrt::Windows::UI::Xaml::Media::Animation::Storyboard const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualState)->put_Storyboard(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::SetterBaseCollection) consume_Windows_UI_Xaml_IVisualState2<D>::Setters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualState2)->get_Setters(&value));
        return winrt::Windows::UI::Xaml::SetterBaseCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::StateTriggerBase>) consume_Windows_UI_Xaml_IVisualState2<D>::StateTriggers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualState2)->get_StateTriggers(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::StateTriggerBase>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VisualState) consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::OldState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs)->get_OldState(&value));
        return winrt::Windows::UI::Xaml::VisualState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::OldState(winrt::Windows::UI::Xaml::VisualState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs)->put_OldState(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VisualState) consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::NewState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs)->get_NewState(&value));
        return winrt::Windows::UI::Xaml::VisualState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::NewState(winrt::Windows::UI::Xaml::VisualState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs)->put_NewState(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Control) consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs)->get_Control(&value));
        return winrt::Windows::UI::Xaml::Controls::Control{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::Control(winrt::Windows::UI::Xaml::Controls::Control const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs)->put_Control(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IVisualStateGroup<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualTransition>) consume_Windows_UI_Xaml_IVisualStateGroup<D>::Transitions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->get_Transitions(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualTransition>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualState>) consume_Windows_UI_Xaml_IVisualStateGroup<D>::States() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->get_States(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualState>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VisualState) consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->get_CurrentState(&value));
        return winrt::Windows::UI::Xaml::VisualState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged(winrt::Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->add_CurrentStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged_revoker consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged(auto_revoke_t, winrt::Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, CurrentStateChanged_revoker>(this, CurrentStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->remove_CurrentStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging(winrt::Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->add_CurrentStateChanging(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging_revoker consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging(auto_revoke_t, winrt::Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, CurrentStateChanging_revoker>(this, CurrentStateChanging(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateGroup)->remove_CurrentStateChanging(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VisualStateManager) consume_Windows_UI_Xaml_IVisualStateManagerFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::VisualStateManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IVisualStateManagerOverrides<D>::GoToStateCore(winrt::Windows::UI::Xaml::Controls::Control const& control, winrt::Windows::UI::Xaml::FrameworkElement const& templateRoot, param::hstring const& stateName, winrt::Windows::UI::Xaml::VisualStateGroup const& group, winrt::Windows::UI::Xaml::VisualState const& state, bool useTransitions) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerOverrides)->GoToStateCore(*(void**)(&control), *(void**)(&templateRoot), *(void**)(&stateName), *(void**)(&group), *(void**)(&state), useTransitions, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateManagerProtected<D>::RaiseCurrentStateChanging(winrt::Windows::UI::Xaml::VisualStateGroup const& stateGroup, winrt::Windows::UI::Xaml::VisualState const& oldState, winrt::Windows::UI::Xaml::VisualState const& newState, winrt::Windows::UI::Xaml::Controls::Control const& control) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerProtected)->RaiseCurrentStateChanging(*(void**)(&stateGroup), *(void**)(&oldState), *(void**)(&newState), *(void**)(&control)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateManagerProtected<D>::RaiseCurrentStateChanged(winrt::Windows::UI::Xaml::VisualStateGroup const& stateGroup, winrt::Windows::UI::Xaml::VisualState const& oldState, winrt::Windows::UI::Xaml::VisualState const& newState, winrt::Windows::UI::Xaml::Controls::Control const& control) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerProtected)->RaiseCurrentStateChanged(*(void**)(&stateGroup), *(void**)(&oldState), *(void**)(&newState), *(void**)(&control)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualStateGroup>) consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::GetVisualStateGroups(winrt::Windows::UI::Xaml::FrameworkElement const& obj) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerStatics)->GetVisualStateGroups(*(void**)(&obj), &result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualStateGroup>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::CustomVisualStateManagerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerStatics)->get_CustomVisualStateManagerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VisualStateManager) consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::GetCustomVisualStateManager(winrt::Windows::UI::Xaml::FrameworkElement const& obj) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerStatics)->GetCustomVisualStateManager(*(void**)(&obj), &result));
        return winrt::Windows::UI::Xaml::VisualStateManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::SetCustomVisualStateManager(winrt::Windows::UI::Xaml::FrameworkElement const& obj, winrt::Windows::UI::Xaml::VisualStateManager const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerStatics)->SetCustomVisualStateManager(*(void**)(&obj), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::GoToState(winrt::Windows::UI::Xaml::Controls::Control const& control, param::hstring const& stateName, bool useTransitions) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualStateManagerStatics)->GoToState(*(void**)(&control), *(void**)(&stateName), useTransitions, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedDuration() const
    {
        winrt::Windows::UI::Xaml::Duration value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->get_GeneratedDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedDuration(winrt::Windows::UI::Xaml::Duration const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->put_GeneratedDuration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedEasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->get_GeneratedEasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedEasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->put_GeneratedEasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IVisualTransition<D>::To() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->get_To(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualTransition<D>::To(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->put_To(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_IVisualTransition<D>::From() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->get_From(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualTransition<D>::From(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->put_From(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::Storyboard) consume_Windows_UI_Xaml_IVisualTransition<D>::Storyboard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->get_Storyboard(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::Storyboard{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IVisualTransition<D>::Storyboard(winrt::Windows::UI::Xaml::Media::Animation::Storyboard const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransition)->put_Storyboard(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VisualTransition) consume_Windows_UI_Xaml_IVisualTransitionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IVisualTransitionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::VisualTransition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_IWindow<D>::Bounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->get_Bounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IWindow<D>::Visible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->get_Visible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IWindow<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->get_Content(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::Content(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->put_Content(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindow) consume_Windows_UI_Xaml_IWindow<D>::CoreWindow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->get_CoreWindow(&value));
        return winrt::Windows::UI::Core::CoreWindow{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcher) consume_Windows_UI_Xaml_IWindow<D>::Dispatcher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->get_Dispatcher(&value));
        return winrt::Windows::UI::Core::CoreDispatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IWindow<D>::Activated(winrt::Windows::UI::Xaml::WindowActivatedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->add_Activated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::Activated_revoker consume_Windows_UI_Xaml_IWindow<D>::Activated(auto_revoke_t, winrt::Windows::UI::Xaml::WindowActivatedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::Activated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->remove_Activated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IWindow<D>::Closed(winrt::Windows::UI::Xaml::WindowClosedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::Closed_revoker consume_Windows_UI_Xaml_IWindow<D>::Closed(auto_revoke_t, winrt::Windows::UI::Xaml::WindowClosedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IWindow<D>::SizeChanged(winrt::Windows::UI::Xaml::WindowSizeChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->add_SizeChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::SizeChanged_revoker consume_Windows_UI_Xaml_IWindow<D>::SizeChanged(auto_revoke_t, winrt::Windows::UI::Xaml::WindowSizeChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::SizeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->remove_SizeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged(winrt::Windows::UI::Xaml::WindowVisibilityChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->add_VisibilityChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged_revoker consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged(auto_revoke_t, winrt::Windows::UI::Xaml::WindowVisibilityChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, VisibilityChanged_revoker>(this, VisibilityChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->remove_VisibilityChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::Activate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->Activate());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IWindow2<D>::SetTitleBar(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow2)->SetTitleBar(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Compositor) consume_Windows_UI_Xaml_IWindow3<D>::Compositor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow3)->get_Compositor(&value));
        return winrt::Windows::UI::Composition::Compositor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIContext) consume_Windows_UI_Xaml_IWindow4<D>::UIContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindow4)->get_UIContext(&value));
        return winrt::Windows::UI::UIContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Window) consume_Windows_UI_Xaml_IWindowCreatedEventArgs<D>::Window() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindowCreatedEventArgs)->get_Window(&value));
        return winrt::Windows::UI::Xaml::Window{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Window) consume_Windows_UI_Xaml_IWindowStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IWindowStatics)->get_Current(&value));
        return winrt::Windows::UI::Xaml::Window{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_IXamlRoot<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->get_Content(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_IXamlRoot<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_IXamlRoot<D>::RasterizationScale() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->get_RasterizationScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_IXamlRoot<D>::IsHostVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->get_IsHostVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIContext) consume_Windows_UI_Xaml_IXamlRoot<D>::UIContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->get_UIContext(&value));
        return winrt::Windows::UI::UIContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_IXamlRoot<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::XamlRoot, winrt::Windows::UI::Xaml::XamlRootChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_IXamlRoot<D>::Changed_revoker consume_Windows_UI_Xaml_IXamlRoot<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::XamlRoot, winrt::Windows::UI::Xaml::XamlRootChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_IXamlRoot<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::IXamlRoot)->remove_Changed(impl::bind_in(token));
    }
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::ApplicationInitializationCallback, H> final : implements_delegate<winrt::Windows::UI::Xaml::ApplicationInitializationCallback, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::ApplicationInitializationCallback, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* p) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::UI::Xaml::ApplicationInitializationCallbackParams const*>(&p));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::BindingFailedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::BindingFailedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::BindingFailedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::BindingFailedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::CreateDefaultValueCallback, H> final : implements_delegate<winrt::Windows::UI::Xaml::CreateDefaultValueCallback, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::CreateDefaultValueCallback, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void** result) noexcept final try
        {
            clear_abi(result);
            *result = detach_from<winrt::Windows::Foundation::IInspectable>((*this)());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::DependencyPropertyChangedCallback, H> final : implements_delegate<winrt::Windows::UI::Xaml::DependencyPropertyChangedCallback, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::DependencyPropertyChangedCallback, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* dp) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::DragEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::DragEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::DragEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::DragEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::EnteredBackgroundEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::EnteredBackgroundEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::EnteredBackgroundEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::ExceptionRoutedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::ExceptionRoutedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::ExceptionRoutedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::ExceptionRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::LeavingBackgroundEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::LeavingBackgroundEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::LeavingBackgroundEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::PropertyChangedCallback, H> final : implements_delegate<winrt::Windows::UI::Xaml::PropertyChangedCallback, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::PropertyChangedCallback, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* d, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&d), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::RoutedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::RoutedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::RoutedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::SizeChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::SizeChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::SizeChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::SizeChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::SuspendingEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::SuspendingEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::SuspendingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::ApplicationModel::SuspendingEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::UnhandledExceptionEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::UnhandledExceptionEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::UnhandledExceptionEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::UnhandledExceptionEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::VisualStateChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::VisualStateChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::VisualStateChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::WindowActivatedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::WindowActivatedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::WindowActivatedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Core::WindowActivatedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::WindowClosedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::WindowClosedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::WindowClosedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Core::CoreWindowEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::WindowSizeChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::WindowSizeChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::WindowSizeChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Core::WindowSizeChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::WindowVisibilityChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::WindowVisibilityChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::WindowVisibilityChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Core::VisibilityChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IAdaptiveTrigger> : produce_base<D, winrt::Windows::UI::Xaml::IAdaptiveTrigger>
    {
        int32_t __stdcall get_MinWindowWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinWindowWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinWindowWidth(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinWindowWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinWindowHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinWindowHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinWindowHeight(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinWindowHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IAdaptiveTriggerFactory> : produce_base<D, winrt::Windows::UI::Xaml::IAdaptiveTriggerFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::AdaptiveTrigger>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics> : produce_base<D, winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics>
    {
        int32_t __stdcall get_MinWindowWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinWindowWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinWindowHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinWindowHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplication> : produce_base<D, winrt::Windows::UI::Xaml::IApplication>
    {
        int32_t __stdcall get_Resources(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ResourceDictionary>(this->shim().Resources());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Resources(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resources(*reinterpret_cast<winrt::Windows::UI::Xaml::ResourceDictionary const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DebugSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DebugSettings>(this->shim().DebugSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedTheme(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ApplicationTheme>(this->shim().RequestedTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequestedTheme(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestedTheme(*reinterpret_cast<winrt::Windows::UI::Xaml::ApplicationTheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_UnhandledException(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UnhandledException(*reinterpret_cast<winrt::Windows::UI::Xaml::UnhandledExceptionEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UnhandledException(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnhandledException(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Suspending(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Suspending(*reinterpret_cast<winrt::Windows::UI::Xaml::SuspendingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Suspending(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Suspending(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Resuming(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Resuming(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Resuming(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resuming(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Exit() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Exit();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplication2> : produce_base<D, winrt::Windows::UI::Xaml::IApplication2>
    {
        int32_t __stdcall get_FocusVisualKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FocusVisualKind>(this->shim().FocusVisualKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusVisualKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusVisualKind(*reinterpret_cast<winrt::Windows::UI::Xaml::FocusVisualKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequiresPointerMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ApplicationRequiresPointerMode>(this->shim().RequiresPointerMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequiresPointerMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequiresPointerMode(*reinterpret_cast<winrt::Windows::UI::Xaml::ApplicationRequiresPointerMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_LeavingBackground(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LeavingBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::LeavingBackgroundEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LeavingBackground(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LeavingBackground(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnteredBackground(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnteredBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::EnteredBackgroundEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnteredBackground(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnteredBackground(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplication3> : produce_base<D, winrt::Windows::UI::Xaml::IApplication3>
    {
        int32_t __stdcall get_HighContrastAdjustment(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ApplicationHighContrastAdjustment>(this->shim().HighContrastAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HighContrastAdjustment(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HighContrastAdjustment(*reinterpret_cast<winrt::Windows::UI::Xaml::ApplicationHighContrastAdjustment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplicationFactory> : produce_base<D, winrt::Windows::UI::Xaml::IApplicationFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Application>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplicationInitializationCallbackParams> : produce_base<D, winrt::Windows::UI::Xaml::IApplicationInitializationCallbackParams>
    {
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplicationOverrides> : produce_base<D, winrt::Windows::UI::Xaml::IApplicationOverrides>
    {
        int32_t __stdcall OnActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnLaunched(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnLaunched(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnFileActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnFileActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::FileActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnSearchActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnSearchActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::SearchActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnShareTargetActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnShareTargetActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnFileOpenPickerActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnFileOpenPickerActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnFileSavePickerActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnFileSavePickerActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnCachedFileUpdaterActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnCachedFileUpdaterActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnWindowCreated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnWindowCreated(*reinterpret_cast<winrt::Windows::UI::Xaml::WindowCreatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplicationOverrides2> : produce_base<D, winrt::Windows::UI::Xaml::IApplicationOverrides2>
    {
        int32_t __stdcall OnBackgroundActivated(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnBackgroundActivated(*reinterpret_cast<winrt::Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IApplicationStatics> : produce_base<D, winrt::Windows::UI::Xaml::IApplicationStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Application>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start(void* callback) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start(*reinterpret_cast<winrt::Windows::UI::Xaml::ApplicationInitializationCallback const*>(&callback));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadComponent(void* component, void* resourceLocator) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoadComponent(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&component), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&resourceLocator));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadComponentWithResourceLocation(void* component, void* resourceLocator, int32_t componentResourceLocation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoadComponent(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&component), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&resourceLocator), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const*>(&componentResourceLocation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IBindingFailedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IBindingFailedEventArgs>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IBringIntoViewOptions> : produce_base<D, winrt::Windows::UI::Xaml::IBringIntoViewOptions>
    {
        int32_t __stdcall get_AnimationDesired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AnimationDesired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AnimationDesired(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AnimationDesired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetRect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>>(this->shim().TargetRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetRect(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetRect(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IBringIntoViewOptions2> : produce_base<D, winrt::Windows::UI::Xaml::IBringIntoViewOptions2>
    {
        int32_t __stdcall get_HorizontalAlignmentRatio(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalAlignmentRatio(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalAlignmentRatio(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VerticalAlignmentRatio(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs>
    {
        int32_t __stdcall get_TargetElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().TargetElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetElement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AnimationDesired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AnimationDesired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AnimationDesired(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AnimationDesired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().TargetRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetRect(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetRect(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalAlignmentRatio(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalAlignmentRatio(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IBrushTransition> : produce_base<D, winrt::Windows::UI::Xaml::IBrushTransition>
    {
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IBrushTransitionFactory> : produce_base<D, winrt::Windows::UI::Xaml::IBrushTransitionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::BrushTransition>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IColorPaletteResources> : produce_base<D, winrt::Windows::UI::Xaml::IColorPaletteResources>
    {
        int32_t __stdcall get_AltHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().AltHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AltHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AltHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AltLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().AltLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AltLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AltLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AltMedium(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().AltMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AltMedium(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AltMedium(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AltMediumHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().AltMediumHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AltMediumHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AltMediumHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AltMediumLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().AltMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AltMediumLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AltMediumLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().BaseHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BaseHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BaseHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().BaseLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BaseLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BaseLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseMedium(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().BaseMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BaseMedium(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BaseMedium(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseMediumHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().BaseMediumHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BaseMediumHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BaseMediumHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseMediumLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().BaseMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BaseMediumLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BaseMediumLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeAltLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeAltLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeAltLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeAltLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeBlackHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeBlackHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeBlackHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeBlackHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeBlackLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeBlackLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeBlackLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeBlackLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeBlackMediumLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeBlackMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeBlackMediumLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeBlackMediumLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeBlackMedium(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeBlackMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeBlackMedium(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeBlackMedium(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeDisabledHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeDisabledHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeDisabledHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeDisabledHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeDisabledLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeDisabledLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeDisabledLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeDisabledLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeHigh(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeHigh(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeHigh(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeMedium(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeMedium(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeMedium(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeMediumLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeMediumLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeMediumLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeWhite(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeWhite());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeWhite(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeWhite(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChromeGray(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ChromeGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChromeGray(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChromeGray(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ListLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ListLow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ListLow(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListMedium(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ListMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ListMedium(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ListMedium(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ErrorText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ErrorText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ErrorText(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Accent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().Accent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Accent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Accent(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IColorPaletteResourcesFactory> : produce_base<D, winrt::Windows::UI::Xaml::IColorPaletteResourcesFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ColorPaletteResources>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ICornerRadiusHelper> : produce_base<D, winrt::Windows::UI::Xaml::ICornerRadiusHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics>
    {
        int32_t __stdcall FromRadii(double topLeft, double topRight, double bottomRight, double bottomLeft, struct struct_Windows_UI_Xaml_CornerRadius* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::CornerRadius>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::CornerRadius>(this->shim().FromRadii(topLeft, topRight, bottomRight, bottomLeft));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromUniformRadius(double uniformRadius, struct struct_Windows_UI_Xaml_CornerRadius* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::CornerRadius>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::CornerRadius>(this->shim().FromUniformRadius(uniformRadius));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataContextChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IDataContextChangedEventArgs>
    {
        int32_t __stdcall get_NewValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataTemplate> : produce_base<D, winrt::Windows::UI::Xaml::IDataTemplate>
    {
        int32_t __stdcall LoadContent(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().LoadContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataTemplateExtension> : produce_base<D, winrt::Windows::UI::Xaml::IDataTemplateExtension>
    {
        int32_t __stdcall ResetTemplate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetTemplate();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessBinding(uint32_t phase, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ProcessBinding(phase));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessBindings(void* arg, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().ProcessBindings(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ContainerContentChangingEventArgs const*>(&arg)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataTemplateFactory> : produce_base<D, winrt::Windows::UI::Xaml::IDataTemplateFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DataTemplate>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataTemplateKey> : produce_base<D, winrt::Windows::UI::Xaml::IDataTemplateKey>
    {
        int32_t __stdcall get_DataType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataType(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataType(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataTemplateKeyFactory> : produce_base<D, winrt::Windows::UI::Xaml::IDataTemplateKeyFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DataTemplateKey>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithType(void* dataType, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DataTemplateKey>(this->shim().CreateInstanceWithType(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dataType), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDataTemplateStatics2> : produce_base<D, winrt::Windows::UI::Xaml::IDataTemplateStatics2>
    {
        int32_t __stdcall get_ExtensionInstanceProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExtensionInstanceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetExtensionInstance(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::IDataTemplateExtension>(this->shim().GetExtensionInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetExtensionInstance(void* element, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetExtensionInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::IDataTemplateExtension const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDebugSettings> : produce_base<D, winrt::Windows::UI::Xaml::IDebugSettings>
    {
        int32_t __stdcall get_EnableFrameRateCounter(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableFrameRateCounter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableFrameRateCounter(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableFrameRateCounter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBindingTracingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBindingTracingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsBindingTracingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsBindingTracingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOverdrawHeatMapEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverdrawHeatMapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsOverdrawHeatMapEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOverdrawHeatMapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_BindingFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BindingFailed(*reinterpret_cast<winrt::Windows::UI::Xaml::BindingFailedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BindingFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BindingFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDebugSettings2> : produce_base<D, winrt::Windows::UI::Xaml::IDebugSettings2>
    {
        int32_t __stdcall get_EnableRedrawRegions(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableRedrawRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableRedrawRegions(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableRedrawRegions(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDebugSettings3> : produce_base<D, winrt::Windows::UI::Xaml::IDebugSettings3>
    {
        int32_t __stdcall get_IsTextPerformanceVisualizationEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTextPerformanceVisualizationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTextPerformanceVisualizationEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTextPerformanceVisualizationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDebugSettings4> : produce_base<D, winrt::Windows::UI::Xaml::IDebugSettings4>
    {
        int32_t __stdcall get_FailFastOnErrors(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().FailFastOnErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FailFastOnErrors(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailFastOnErrors(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyObject> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyObject>
    {
        int32_t __stdcall GetValue(void* dp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetValue(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetValue(void* dp, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetValue(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearValue(void* dp) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearValue(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadLocalValue(void* dp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ReadLocalValue(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnimationBaseValue(void* dp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetAnimationBaseValue(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Dispatcher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyObject2> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyObject2>
    {
        int32_t __stdcall RegisterPropertyChangedCallback(void* dp, void* callback, int64_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int64_t>(this->shim().RegisterPropertyChangedCallback(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyPropertyChangedCallback const*>(&callback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterPropertyChangedCallback(void* dp, int64_t token) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterPropertyChangedCallback(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp), token);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyObjectCollectionFactory> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyObjectCollectionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObjectCollection>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyObjectFactory> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyObjectFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyProperty> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyProperty>
    {
        int32_t __stdcall GetMetadata(struct struct_Windows_UI_Xaml_Interop_TypeName forType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().GetMetadata(*reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&forType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs>
    {
        int32_t __stdcall get_Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OldValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().OldValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDependencyPropertyStatics> : produce_base<D, winrt::Windows::UI::Xaml::IDependencyPropertyStatics>
    {
        int32_t __stdcall get_UnsetValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().UnsetValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Register(void* name, struct struct_Windows_UI_Xaml_Interop_TypeName propertyType, struct struct_Windows_UI_Xaml_Interop_TypeName ownerType, void* typeMetadata, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().Register(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&propertyType), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&ownerType), *reinterpret_cast<winrt::Windows::UI::Xaml::PropertyMetadata const*>(&typeMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAttached(void* name, struct struct_Windows_UI_Xaml_Interop_TypeName propertyType, struct struct_Windows_UI_Xaml_Interop_TypeName ownerType, void* defaultMetadata, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RegisterAttached(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&propertyType), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&ownerType), *reinterpret_cast<winrt::Windows::UI::Xaml::PropertyMetadata const*>(&defaultMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDispatcherTimer> : produce_base<D, winrt::Windows::UI::Xaml::IDispatcherTimer>
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
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Tick(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Tick(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Tick(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tick(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
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
    struct produce<D, winrt::Windows::UI::Xaml::IDispatcherTimerFactory> : produce_base<D, winrt::Windows::UI::Xaml::IDispatcherTimerFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DispatcherTimer>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IDragEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackage>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPosition(void* relativeTo, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::IDragEventArgs2>
    {
        int32_t __stdcall get_DataView(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().DataView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragUIOverride(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DragUIOverride>(this->shim().DragUIOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Modifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers>(this->shim().Modifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AcceptedOperation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().AcceptedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AcceptedOperation(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceptedOperation(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DragOperationDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragEventArgs3> : produce_base<D, winrt::Windows::UI::Xaml::IDragEventArgs3>
    {
        int32_t __stdcall get_AllowedOperations(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().AllowedOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragOperationDeferral> : produce_base<D, winrt::Windows::UI::Xaml::IDragOperationDeferral>
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
    struct produce<D, winrt::Windows::UI::Xaml::IDragStartingEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IDragStartingEventArgs>
    {
        int32_t __stdcall get_Cancel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Cancel(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackage>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragUI(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DragUI>(this->shim().DragUI());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DragOperationDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPosition(void* relativeTo, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragStartingEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::IDragStartingEventArgs2>
    {
        int32_t __stdcall get_AllowedOperations(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().AllowedOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowedOperations(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowedOperations(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragUI> : produce_base<D, winrt::Windows::UI::Xaml::IDragUI>
    {
        int32_t __stdcall SetContentFromBitmapImage(void* bitmapImage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromBitmapImageWithAnchorPoint(void* bitmapImage, winrt::Windows::Foundation::Point anchorPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromSoftwareBitmap(void* softwareBitmap) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromSoftwareBitmapWithAnchorPoint(void* softwareBitmap, winrt::Windows::Foundation::Point anchorPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromDataPackage() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromDataPackage();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDragUIOverride> : produce_base<D, winrt::Windows::UI::Xaml::IDragUIOverride>
    {
        int32_t __stdcall get_Caption(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Caption(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Caption(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsContentVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsContentVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsContentVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsContentVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCaptionVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCaptionVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCaptionVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCaptionVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGlyphVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGlyphVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsGlyphVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsGlyphVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clear() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromBitmapImage(void* bitmapImage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromBitmapImageWithAnchorPoint(void* bitmapImage, winrt::Windows::Foundation::Point anchorPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromSoftwareBitmap(void* softwareBitmap) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentFromSoftwareBitmapWithAnchorPoint(void* softwareBitmap, winrt::Windows::Foundation::Point anchorPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDropCompletedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IDropCompletedEventArgs>
    {
        int32_t __stdcall get_DropResult(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().DropResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDurationHelper> : produce_base<D, winrt::Windows::UI::Xaml::IDurationHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IDurationHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::IDurationHelperStatics>
    {
        int32_t __stdcall get_Automatic(struct struct_Windows_UI_Xaml_Duration* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().Automatic());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Forever(struct struct_Windows_UI_Xaml_Duration* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().Forever());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Compare(struct struct_Windows_UI_Xaml_Duration duration1, struct struct_Windows_UI_Xaml_Duration duration2, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().Compare(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&duration1), *reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&duration2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromTimeSpan(int64_t timeSpan, struct struct_Windows_UI_Xaml_Duration* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().FromTimeSpan(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timeSpan)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHasTimeSpan(struct struct_Windows_UI_Xaml_Duration target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetHasTimeSpan(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Add(struct struct_Windows_UI_Xaml_Duration target, struct struct_Windows_UI_Xaml_Duration duration, struct struct_Windows_UI_Xaml_Duration* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().Add(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&target), *reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Equals(struct struct_Windows_UI_Xaml_Duration target, struct struct_Windows_UI_Xaml_Duration value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&target), *reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Subtract(struct struct_Windows_UI_Xaml_Duration target, struct struct_Windows_UI_Xaml_Duration duration, struct struct_Windows_UI_Xaml_Duration* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().Subtract(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&target), *reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs>
    {
        int32_t __stdcall get_EffectiveViewport(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().EffectiveViewport());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxViewport(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().MaxViewport());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BringIntoViewDistanceX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().BringIntoViewDistanceX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BringIntoViewDistanceY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().BringIntoViewDistanceY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementFactory> : produce_base<D, winrt::Windows::UI::Xaml::IElementFactory>
    {
        int32_t __stdcall GetElement(void* args, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().GetElement(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementFactoryGetArgs const*>(&args)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RecycleElement(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecycleElement(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementFactoryGetArgs> : produce_base<D, winrt::Windows::UI::Xaml::IElementFactoryGetArgs>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Parent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Parent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Parent(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementFactoryGetArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::IElementFactoryGetArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementFactoryGetArgs>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs> : produce_base<D, winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs>
    {
        int32_t __stdcall get_Element(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Element());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Element(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Element(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Parent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Parent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Parent(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementFactoryRecycleArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::IElementFactoryRecycleArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementSoundPlayer> : produce_base<D, winrt::Windows::UI::Xaml::IElementSoundPlayer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementSoundPlayerStatics> : produce_base<D, winrt::Windows::UI::Xaml::IElementSoundPlayerStatics>
    {
        int32_t __stdcall get_Volume(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Volume(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Volume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementSoundPlayerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_State(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().State(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementSoundPlayerState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Play(int32_t sound) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Play(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementSoundKind const*>(&sound));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2> : produce_base<D, winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2>
    {
        int32_t __stdcall get_SpatialAudioMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementSpatialAudioMode>(this->shim().SpatialAudioMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpatialAudioMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpatialAudioMode(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementSpatialAudioMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IEventTrigger> : produce_base<D, winrt::Windows::UI::Xaml::IEventTrigger>
    {
        int32_t __stdcall get_RoutedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().RoutedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoutedEvent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoutedEvent(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEvent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Actions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::TriggerActionCollection>(this->shim().Actions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IExceptionRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IExceptionRoutedEventArgs>
    {
        int32_t __stdcall get_ErrorMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ErrorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IExceptionRoutedEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::IExceptionRoutedEventArgsFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElement> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElement>
    {
        int32_t __stdcall get_Triggers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::TriggerCollection>(this->shim().Triggers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Resources(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ResourceDictionary>(this->shim().Resources());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Resources(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resources(*reinterpret_cast<winrt::Windows::UI::Xaml::ResourceDictionary const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
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
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Language(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ActualWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ActualHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Width(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Width(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Width(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Height(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Height(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinWidth(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxWidth(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinHeight(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxHeight(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::HorizontalAlignment>(this->shim().HorizontalAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::HorizontalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VerticalAlignment>(this->shim().VerticalAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VerticalAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::VerticalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Margin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().Margin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Margin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Margin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
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
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().BaseUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().DataContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataContext(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataContext(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Style(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Style>(this->shim().Style());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Style(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Style(*reinterpret_cast<winrt::Windows::UI::Xaml::Style const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Parent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlowDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FlowDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FlowDirection(*reinterpret_cast<winrt::Windows::UI::Xaml::FlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Loaded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Loaded(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Loaded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Loaded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Unloaded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Unloaded(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Unloaded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Unloaded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SizeChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::SizeChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SizeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LayoutUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LayoutUpdated(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LayoutUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LayoutUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall FindName(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().FindName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBinding(void* dp, void* binding) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBinding(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<winrt::Windows::UI::Xaml::Data::BindingBase const*>(&binding));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElement2> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElement2>
    {
        int32_t __stdcall get_RequestedTheme(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementTheme>(this->shim().RequestedTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequestedTheme(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestedTheme(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementTheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DataContextChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DataContextChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::DataContextChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DataContextChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataContextChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetBindingExpression(void* dp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Data::BindingExpression>(this->shim().GetBindingExpression(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElement3> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElement3>
    {
        int32_t __stdcall add_Loading(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Loading(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Loading(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Loading(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElement4> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElement4>
    {
        int32_t __stdcall get_AllowFocusOnInteraction(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowFocusOnInteraction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowFocusOnInteraction(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowFocusOnInteraction(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().FocusVisualMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusVisualMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusVisualMargin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualSecondaryThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().FocusVisualSecondaryThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusVisualSecondaryThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusVisualSecondaryThickness(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualPrimaryThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().FocusVisualPrimaryThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusVisualPrimaryThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusVisualPrimaryThickness(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualSecondaryBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().FocusVisualSecondaryBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusVisualSecondaryBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusVisualSecondaryBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualPrimaryBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().FocusVisualPrimaryBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusVisualPrimaryBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusVisualPrimaryBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowFocusWhenDisabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowFocusWhenDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowFocusWhenDisabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowFocusWhenDisabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElement6> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElement6>
    {
        int32_t __stdcall get_ActualTheme(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementTheme>(this->shim().ActualTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ActualThemeChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ActualThemeChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ActualThemeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ActualThemeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElement7> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElement7>
    {
        int32_t __stdcall get_IsLoaded(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLoaded());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_EffectiveViewportChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EffectiveViewportChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EffectiveViewportChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EffectiveViewportChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementFactory> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FrameworkElement>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides>
    {
        int32_t __stdcall MeasureOverride(winrt::Windows::Foundation::Size availableSize, winrt::Windows::Foundation::Size* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Size>(this->shim().MeasureOverride(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&availableSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ArrangeOverride(winrt::Windows::Foundation::Size finalSize, winrt::Windows::Foundation::Size* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Size>(this->shim().ArrangeOverride(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&finalSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnApplyTemplate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnApplyTemplate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2>
    {
        int32_t __stdcall GoToElementStateCore(void* stateName, bool useTransitions, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GoToElementStateCore(*reinterpret_cast<hstring const*>(&stateName), useTransitions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementProtected7> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementProtected7>
    {
        int32_t __stdcall InvalidateViewport() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InvalidateViewport();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics>
    {
        int32_t __stdcall get_TagProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TagProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LanguageProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LanguageProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ActualWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ActualHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().WidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MaxWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MaxHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().VerticalAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().NameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataContextProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DataContextProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StyleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlowDirectionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FlowDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics2> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics2>
    {
        int32_t __stdcall get_RequestedThemeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RequestedThemeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics4> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics4>
    {
        int32_t __stdcall get_AllowFocusOnInteractionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusOnInteractionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualMarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualSecondaryThicknessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualSecondaryThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualPrimaryThicknessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualPrimaryThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualSecondaryBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualSecondaryBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusVisualPrimaryBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualPrimaryBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowFocusWhenDisabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusWhenDisabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics5> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics5>
    {
        int32_t __stdcall DeferTree(void* element) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeferTree(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics6> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkElementStatics6>
    {
        int32_t __stdcall get_ActualThemeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ActualThemeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkTemplate> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkTemplate>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkTemplateFactory> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkTemplateFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FrameworkTemplate>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkView> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkView>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IFrameworkViewSource> : produce_base<D, winrt::Windows::UI::Xaml::IFrameworkViewSource>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IGridLengthHelper> : produce_base<D, winrt::Windows::UI::Xaml::IGridLengthHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IGridLengthHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::IGridLengthHelperStatics>
    {
        int32_t __stdcall get_Auto(struct struct_Windows_UI_Xaml_GridLength* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::GridLength>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::GridLength>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromPixels(double pixels, struct struct_Windows_UI_Xaml_GridLength* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::GridLength>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::GridLength>(this->shim().FromPixels(pixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromValueAndType(double value, int32_t type, struct struct_Windows_UI_Xaml_GridLength* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::GridLength>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::GridLength>(this->shim().FromValueAndType(value, *reinterpret_cast<winrt::Windows::UI::Xaml::GridUnitType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsAbsolute(struct struct_Windows_UI_Xaml_GridLength target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsAbsolute(*reinterpret_cast<winrt::Windows::UI::Xaml::GridLength const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsAuto(struct struct_Windows_UI_Xaml_GridLength target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsAuto(*reinterpret_cast<winrt::Windows::UI::Xaml::GridLength const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsStar(struct struct_Windows_UI_Xaml_GridLength target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsStar(*reinterpret_cast<winrt::Windows::UI::Xaml::GridLength const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Equals(struct struct_Windows_UI_Xaml_GridLength target, struct struct_Windows_UI_Xaml_GridLength value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<winrt::Windows::UI::Xaml::GridLength const*>(&target), *reinterpret_cast<winrt::Windows::UI::Xaml::GridLength const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IMediaFailedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IMediaFailedRoutedEventArgs>
    {
        int32_t __stdcall get_ErrorTrace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ErrorTrace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPointHelper> : produce_base<D, winrt::Windows::UI::Xaml::IPointHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPointHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::IPointHelperStatics>
    {
        int32_t __stdcall FromCoordinates(float x, float y, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().FromCoordinates(x, y));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPropertyMetadata> : produce_base<D, winrt::Windows::UI::Xaml::IPropertyMetadata>
    {
        int32_t __stdcall get_DefaultValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().DefaultValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CreateDefaultValueCallback(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::CreateDefaultValueCallback>(this->shim().CreateDefaultValueCallback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPropertyMetadataFactory> : produce_base<D, winrt::Windows::UI::Xaml::IPropertyMetadataFactory>
    {
        int32_t __stdcall CreateInstanceWithDefaultValue(void* defaultValue, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().CreateInstanceWithDefaultValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&defaultValue), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithDefaultValueAndCallback(void* defaultValue, void* propertyChangedCallback, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().CreateInstanceWithDefaultValueAndCallback(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&defaultValue), *reinterpret_cast<winrt::Windows::UI::Xaml::PropertyChangedCallback const*>(&propertyChangedCallback), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPropertyMetadataStatics> : produce_base<D, winrt::Windows::UI::Xaml::IPropertyMetadataStatics>
    {
        int32_t __stdcall CreateWithDefaultValue(void* defaultValue, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithDefaultValueAndCallback(void* defaultValue, void* propertyChangedCallback, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&defaultValue), *reinterpret_cast<winrt::Windows::UI::Xaml::PropertyChangedCallback const*>(&propertyChangedCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithFactory(void* createDefaultValueCallback, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Xaml::CreateDefaultValueCallback const*>(&createDefaultValueCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithFactoryAndCallback(void* createDefaultValueCallback, void* propertyChangedCallback, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Xaml::CreateDefaultValueCallback const*>(&createDefaultValueCallback), *reinterpret_cast<winrt::Windows::UI::Xaml::PropertyChangedCallback const*>(&propertyChangedCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPropertyPath> : produce_base<D, winrt::Windows::UI::Xaml::IPropertyPath>
    {
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IPropertyPathFactory> : produce_base<D, winrt::Windows::UI::Xaml::IPropertyPathFactory>
    {
        int32_t __stdcall CreateInstance(void* path, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::PropertyPath>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IRectHelper> : produce_base<D, winrt::Windows::UI::Xaml::IRectHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IRectHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::IRectHelperStatics>
    {
        int32_t __stdcall get_Empty(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Empty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromCoordinatesAndDimensions(float x, float y, float width, float height, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().FromCoordinatesAndDimensions(x, y, width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromPoints(winrt::Windows::Foundation::Point point1, winrt::Windows::Foundation::Point point2, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().FromPoints(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point1), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromLocationAndSize(winrt::Windows::Foundation::Point location, winrt::Windows::Foundation::Size size, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().FromLocationAndSize(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&location), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsEmpty(winrt::Windows::Foundation::Rect target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsEmpty(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBottom(winrt::Windows::Foundation::Rect target, float* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<float>(this->shim().GetBottom(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLeft(winrt::Windows::Foundation::Rect target, float* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<float>(this->shim().GetLeft(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRight(winrt::Windows::Foundation::Rect target, float* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<float>(this->shim().GetRight(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTop(winrt::Windows::Foundation::Rect target, float* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<float>(this->shim().GetTop(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Contains(winrt::Windows::Foundation::Rect target, winrt::Windows::Foundation::Point point, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Contains(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Equals(winrt::Windows::Foundation::Rect target, winrt::Windows::Foundation::Rect value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Intersect(winrt::Windows::Foundation::Rect target, winrt::Windows::Foundation::Rect rect, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Intersect(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnionWithPoint(winrt::Windows::Foundation::Rect target, winrt::Windows::Foundation::Point point, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Union(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnionWithRect(winrt::Windows::Foundation::Rect target, winrt::Windows::Foundation::Rect rect, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Union(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IResourceDictionary> : produce_base<D, winrt::Windows::UI::Xaml::IResourceDictionary>
    {
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MergedDictionaries(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::ResourceDictionary>>(this->shim().MergedDictionaries());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThemeDictionaries(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>>(this->shim().ThemeDictionaries());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IResourceDictionaryFactory> : produce_base<D, winrt::Windows::UI::Xaml::IResourceDictionaryFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ResourceDictionary>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IRoutedEvent> : produce_base<D, winrt::Windows::UI::Xaml::IRoutedEvent>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IRoutedEventArgs>
    {
        int32_t __stdcall get_OriginalSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().OriginalSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IRoutedEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::IRoutedEventArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IScalarTransition> : produce_base<D, winrt::Windows::UI::Xaml::IScalarTransition>
    {
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IScalarTransitionFactory> : produce_base<D, winrt::Windows::UI::Xaml::IScalarTransitionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ScalarTransition>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISetter> : produce_base<D, winrt::Windows::UI::Xaml::ISetter>
    {
        int32_t __stdcall get_Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Property(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Property(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISetter2> : produce_base<D, winrt::Windows::UI::Xaml::ISetter2>
    {
        int32_t __stdcall get_Target(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::TargetPropertyPath>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Target(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Target(*reinterpret_cast<winrt::Windows::UI::Xaml::TargetPropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISetterBase> : produce_base<D, winrt::Windows::UI::Xaml::ISetterBase>
    {
        int32_t __stdcall get_IsSealed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSealed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISetterBaseCollection> : produce_base<D, winrt::Windows::UI::Xaml::ISetterBaseCollection>
    {
        int32_t __stdcall get_IsSealed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSealed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISetterBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::ISetterBaseFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISetterFactory> : produce_base<D, winrt::Windows::UI::Xaml::ISetterFactory>
    {
        int32_t __stdcall CreateInstance(void* targetProperty, void* value, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::UI::Xaml::Setter>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&targetProperty), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISizeChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::ISizeChangedEventArgs>
    {
        int32_t __stdcall get_PreviousSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().PreviousSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().NewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISizeHelper> : produce_base<D, winrt::Windows::UI::Xaml::ISizeHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ISizeHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::ISizeHelperStatics>
    {
        int32_t __stdcall get_Empty(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Empty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromDimensions(float width, float height, winrt::Windows::Foundation::Size* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Size>(this->shim().FromDimensions(width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsEmpty(winrt::Windows::Foundation::Size target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsEmpty(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Equals(winrt::Windows::Foundation::Size target, winrt::Windows::Foundation::Size value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStateTrigger> : produce_base<D, winrt::Windows::UI::Xaml::IStateTrigger>
    {
        int32_t __stdcall get_IsActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsActive(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsActive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStateTriggerBase> : produce_base<D, winrt::Windows::UI::Xaml::IStateTriggerBase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStateTriggerBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::IStateTriggerBaseFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::StateTriggerBase>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStateTriggerBaseProtected> : produce_base<D, winrt::Windows::UI::Xaml::IStateTriggerBaseProtected>
    {
        int32_t __stdcall SetActive(bool IsActive) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetActive(IsActive);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStateTriggerStatics> : produce_base<D, winrt::Windows::UI::Xaml::IStateTriggerStatics>
    {
        int32_t __stdcall get_IsActiveProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsActiveProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStyle> : produce_base<D, winrt::Windows::UI::Xaml::IStyle>
    {
        int32_t __stdcall get_IsSealed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSealed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Setters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::SetterBaseCollection>(this->shim().Setters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Interop::TypeName>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Interop::TypeName>(this->shim().TargetType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetType(struct struct_Windows_UI_Xaml_Interop_TypeName value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetType(*reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BasedOn(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Style>(this->shim().BasedOn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BasedOn(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BasedOn(*reinterpret_cast<winrt::Windows::UI::Xaml::Style const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Seal() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Seal();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IStyleFactory> : produce_base<D, winrt::Windows::UI::Xaml::IStyleFactory>
    {
        int32_t __stdcall CreateInstance(struct struct_Windows_UI_Xaml_Interop_TypeName targetType, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Style>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&targetType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ITargetPropertyPath> : produce_base<D, winrt::Windows::UI::Xaml::ITargetPropertyPath>
    {
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::PropertyPath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Path(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Path(*reinterpret_cast<winrt::Windows::UI::Xaml::PropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Target(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Target(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Target(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ITargetPropertyPathFactory> : produce_base<D, winrt::Windows::UI::Xaml::ITargetPropertyPathFactory>
    {
        int32_t __stdcall CreateInstance(void* targetProperty, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::TargetPropertyPath>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&targetProperty)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IThicknessHelper> : produce_base<D, winrt::Windows::UI::Xaml::IThicknessHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IThicknessHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::IThicknessHelperStatics>
    {
        int32_t __stdcall FromLengths(double left, double top, double right, double bottom, struct struct_Windows_UI_Xaml_Thickness* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().FromLengths(left, top, right, bottom));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromUniformLength(double uniformLength, struct struct_Windows_UI_Xaml_Thickness* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().FromUniformLength(uniformLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ITriggerAction> : produce_base<D, winrt::Windows::UI::Xaml::ITriggerAction>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ITriggerActionFactory> : produce_base<D, winrt::Windows::UI::Xaml::ITriggerActionFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ITriggerBase> : produce_base<D, winrt::Windows::UI::Xaml::ITriggerBase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::ITriggerBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::ITriggerBaseFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement>
    {
        int32_t __stdcall get_DesiredSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().DesiredSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowDrop(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowDrop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowDrop(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowDrop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Opacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Opacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Clip(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::RectangleGeometry>(this->shim().Clip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Clip(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clip(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::RectangleGeometry const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenderTransform(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Transform>(this->shim().RenderTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RenderTransform(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RenderTransform(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Transform const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Projection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Projection>(this->shim().Projection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Projection(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Projection(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Projection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenderTransformOrigin(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().RenderTransformOrigin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RenderTransformOrigin(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RenderTransformOrigin(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHitTestVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHitTestVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsHitTestVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsHitTestVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Visibility(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Visibility>(this->shim().Visibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Visibility(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Visibility(*reinterpret_cast<winrt::Windows::UI::Xaml::Visibility const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenderSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().RenderSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UseLayoutRounding(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UseLayoutRounding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UseLayoutRounding(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UseLayoutRounding(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Transitions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection>(this->shim().Transitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Transitions(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Transitions(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CacheMode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::CacheMode>(this->shim().CacheMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CacheMode(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CacheMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::CacheMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTapEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTapEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDoubleTapEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDoubleTapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDoubleTapEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDoubleTapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRightTapEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRightTapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsRightTapEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRightTapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHoldingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHoldingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsHoldingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsHoldingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationMode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::ManipulationModes>(this->shim().ManipulationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ManipulationMode(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationModes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerCaptures(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Input::Pointer>>(this->shim().PointerCaptures());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_KeyUp(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyUp(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_KeyDown(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyDown(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GotFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LostFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LostFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DragEnter(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragEnter(*reinterpret_cast<winrt::Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragEnter(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragEnter(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DragLeave(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragLeave(*reinterpret_cast<winrt::Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragLeave(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragLeave(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DragOver(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragOver(*reinterpret_cast<winrt::Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragOver(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragOver(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Drop(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Drop(*reinterpret_cast<winrt::Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Drop(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Drop(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerPressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerPressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerMoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerMoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerReleased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerReleased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerEntered(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerEntered(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerExited(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerExited(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerCaptureLost(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerCaptureLost(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerCaptureLost(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerCaptureLost(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerCanceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerCanceled(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerCanceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PointerWheelChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PointerWheelChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerWheelChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerWheelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Tapped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Tapped(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::TappedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Tapped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tapped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DoubleTapped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DoubleTapped(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::DoubleTappedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DoubleTapped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DoubleTapped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Holding(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Holding(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::HoldingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Holding(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Holding(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RightTapped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RightTapped(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::RightTappedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RightTapped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RightTapped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarting(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationStartingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationInertiaStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationInertiaStarting(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationInertiaStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationInertiaStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarted(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationStartedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationDelta(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationDelta(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationDelta(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationDelta(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCompleted(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Measure(winrt::Windows::Foundation::Size availableSize) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Measure(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&availableSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Arrange(winrt::Windows::Foundation::Rect finalRect) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Arrange(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&finalRect));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CapturePointer(void* value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CapturePointer(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::Pointer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleasePointerCapture(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleasePointerCapture(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::Pointer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleasePointerCaptures() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleasePointerCaptures();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddHandler(void* routedEvent, void* handler, bool handledEventsToo) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddHandler(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEvent const*>(&routedEvent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&handler), handledEventsToo);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveHandler(void* routedEvent, void* handler) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveHandler(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEvent const*>(&routedEvent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&handler));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransformToVisual(void* visual, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::GeneralTransform>(this->shim().TransformToVisual(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&visual)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InvalidateMeasure() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InvalidateMeasure();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InvalidateArrange() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InvalidateArrange();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateLayout() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateLayout();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement10> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement10>
    {
        int32_t __stdcall get_ActualOffset(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().ActualOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualSize(winrt::Windows::Foundation::Numerics::float2* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float2>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float2>(this->shim().ActualSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XamlRoot(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::XamlRoot>(this->shim().XamlRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XamlRoot(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XamlRoot(*reinterpret_cast<winrt::Windows::UI::Xaml::XamlRoot const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UIContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Shadow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Shadow>(this->shim().Shadow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Shadow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Shadow(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Shadow const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement2> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement2>
    {
        int32_t __stdcall get_CompositeMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::ElementCompositeMode>(this->shim().CompositeMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompositeMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompositeMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::ElementCompositeMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CancelDirectManipulations(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CancelDirectManipulations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement3> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement3>
    {
        int32_t __stdcall get_Transform3D(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Media3D::Transform3D>(this->shim().Transform3D());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Transform3D(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Transform3D(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Media3D::Transform3D const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanDrag(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanDrag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanDrag(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanDrag(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DragStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DragStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DropCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DropCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DropCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DropCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DropCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall StartDragAsync(void* pointerPoint, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>>(this->shim().StartDragAsync(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement4> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement4>
    {
        int32_t __stdcall get_ContextFlyout(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase>(this->shim().ContextFlyout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContextFlyout(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContextFlyout(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitDisplayModeOnAccessKeyInvoked(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ExitDisplayModeOnAccessKeyInvoked());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitDisplayModeOnAccessKeyInvoked(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitDisplayModeOnAccessKeyInvoked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAccessKeyScope(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAccessKeyScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAccessKeyScope(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAccessKeyScope(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKeyScopeOwner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().AccessKeyScopeOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccessKeyScopeOwner(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyScopeOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKey(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccessKey(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ContextRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ContextRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::ContextRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContextRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContextRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ContextCanceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ContextCanceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::RoutedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContextCanceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContextCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AccessKeyDisplayRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessKeyDisplayRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyDisplayRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AccessKeyDisplayDismissed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessKeyDisplayDismissed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AccessKeyInvoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyInvoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessKeyInvoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement5> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement5>
    {
        int32_t __stdcall get_Lights(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Media::XamlLight>>(this->shim().Lights());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipPlacementMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode>(this->shim().KeyTipPlacementMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipPlacementMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipPlacementMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyTipHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyTipVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusKeyboardNavigation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode>(this->shim().XYFocusKeyboardNavigation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusKeyboardNavigation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusKeyboardNavigation(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusUpNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusUpNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusUpNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusDownNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusDownNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusDownNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusLeftNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusLeftNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusLeftNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusRightNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusRightNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusRightNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighContrastAdjustment(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementHighContrastAdjustment>(this->shim().HighContrastAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HighContrastAdjustment(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HighContrastAdjustment(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementHighContrastAdjustment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TabFocusNavigation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::KeyboardNavigationMode>(this->shim().TabFocusNavigation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TabFocusNavigation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabFocusNavigation(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyboardNavigationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_GettingFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GettingFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GettingFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GettingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LosingFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LosingFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LosingFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LosingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NoFocusCandidateFound(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NoFocusCandidateFound(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NoFocusCandidateFound(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NoFocusCandidateFound(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall StartBringIntoView() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartBringIntoView();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartBringIntoViewWithOptions(void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartBringIntoView(*reinterpret_cast<winrt::Windows::UI::Xaml::BringIntoViewOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement7> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement7>
    {
        int32_t __stdcall get_KeyboardAccelerators(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>>(this->shim().KeyboardAccelerators());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CharacterReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CharacterReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CharacterReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ProcessKeyboardAccelerators(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ProcessKeyboardAccelerators(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ProcessKeyboardAccelerators(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessKeyboardAccelerators(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PreviewKeyDown(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PreviewKeyDown(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PreviewKeyDown(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviewKeyDown(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PreviewKeyUp(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PreviewKeyUp(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PreviewKeyUp(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviewKeyUp(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall TryInvokeKeyboardAccelerator(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TryInvokeKeyboardAccelerator(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement8> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement8>
    {
        int32_t __stdcall get_KeyTipTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().KeyTipTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyboardAcceleratorPlacementTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().KeyboardAcceleratorPlacementTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyboardAcceleratorPlacementTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyboardAcceleratorPlacementTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyboardAcceleratorPlacementMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode>(this->shim().KeyboardAcceleratorPlacementMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyboardAcceleratorPlacementMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyboardAcceleratorPlacementMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_BringIntoViewRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BringIntoViewRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BringIntoViewRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BringIntoViewRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElement9> : produce_base<D, winrt::Windows::UI::Xaml::IUIElement9>
    {
        int32_t __stdcall get_CanBeScrollAnchor(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanBeScrollAnchor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanBeScrollAnchor(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanBeScrollAnchor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpacityTransition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ScalarTransition>(this->shim().OpacityTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpacityTransition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpacityTransition(*reinterpret_cast<winrt::Windows::UI::Xaml::ScalarTransition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Translation(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Translation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Translation(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Translation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslationTransition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Vector3Transition>(this->shim().TranslationTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslationTransition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslationTransition(*reinterpret_cast<winrt::Windows::UI::Xaml::Vector3Transition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rotation(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Rotation(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rotation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationTransition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ScalarTransition>(this->shim().RotationTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationTransition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationTransition(*reinterpret_cast<winrt::Windows::UI::Xaml::ScalarTransition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scale(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Scale(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Scale(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleTransition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Vector3Transition>(this->shim().ScaleTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleTransition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleTransition(*reinterpret_cast<winrt::Windows::UI::Xaml::Vector3Transition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransformMatrix(winrt::Windows::Foundation::Numerics::float4x4* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float4x4>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float4x4>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransformMatrix(winrt::Windows::Foundation::Numerics::float4x4 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransformMatrix(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float4x4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterPoint(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CenterPoint(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CenterPoint(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationAxis(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().RotationAxis());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationAxis(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationAxis(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAnimation(void* animation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartAnimation(*reinterpret_cast<winrt::Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAnimation(void* animation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopAnimation(*reinterpret_cast<winrt::Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementFactory> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementFactory>
    {
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementOverrides> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementOverrides>
    {
        int32_t __stdcall OnCreateAutomationPeer(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().OnCreateAutomationPeer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnDisconnectVisualChildren() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnDisconnectVisualChildren();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindSubElementsForTouchTargeting(winrt::Windows::Foundation::Point point, winrt::Windows::Foundation::Rect boundingRect, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Point>>>(this->shim().FindSubElementsForTouchTargeting(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&boundingRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementOverrides7> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementOverrides7>
    {
        int32_t __stdcall GetChildrenInTabFocusOrder(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::DependencyObject>>(this->shim().GetChildrenInTabFocusOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnProcessKeyboardAccelerators(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnProcessKeyboardAccelerators(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementOverrides8> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementOverrides8>
    {
        int32_t __stdcall OnKeyboardAcceleratorInvoked(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnKeyboardAcceleratorInvoked(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnBringIntoViewRequested(void* e) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnBringIntoViewRequested(*reinterpret_cast<winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementOverrides9> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementOverrides9>
    {
        int32_t __stdcall PopulatePropertyInfoOverride(void* propertyName, void* animationPropertyInfo) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PopulatePropertyInfoOverride(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<winrt::Windows::UI::Composition::AnimationPropertyInfo const*>(&animationPropertyInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics>
    {
        int32_t __stdcall get_KeyDownEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().KeyDownEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyUpEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().KeyUpEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerEnteredEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerEnteredEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerPressedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerPressedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerMovedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerMovedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerReleasedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerReleasedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerExitedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerExitedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerCaptureLostEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerCaptureLostEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerCanceledEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerCanceledEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerWheelChangedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PointerWheelChangedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TappedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().TappedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DoubleTappedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().DoubleTappedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HoldingEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().HoldingEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RightTappedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().RightTappedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationStartingEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationStartingEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationInertiaStartingEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationInertiaStartingEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationStartedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationStartedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationDeltaEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationDeltaEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationCompletedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationCompletedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragEnterEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().DragEnterEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragLeaveEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().DragLeaveEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragOverEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().DragOverEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DropEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().DropEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowDropProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AllowDropProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpacityProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClipProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClipProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenderTransformProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RenderTransformProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProjectionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ProjectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenderTransformOriginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RenderTransformOriginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHitTestVisibleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsHitTestVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VisibilityProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().VisibilityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UseLayoutRoundingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().UseLayoutRoundingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransitionsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TransitionsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CacheModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CacheModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTapEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsTapEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDoubleTapEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsDoubleTapEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRightTapEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsRightTapEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHoldingEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsHoldingEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ManipulationModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerCapturesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerCapturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics10> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics10>
    {
        int32_t __stdcall get_ShadowProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ShadowProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics2> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics2>
    {
        int32_t __stdcall get_CompositeModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CompositeModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics3> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics3>
    {
        int32_t __stdcall get_Transform3DProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().Transform3DProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanDragProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CanDragProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStartDirectManipulation(void* value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryStartDirectManipulation(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::Pointer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics4> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics4>
    {
        int32_t __stdcall get_ContextFlyoutProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContextFlyoutProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitDisplayModeOnAccessKeyInvokedProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitDisplayModeOnAccessKeyInvokedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAccessKeyScopeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsAccessKeyScopeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKeyScopeOwnerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyScopeOwnerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKeyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics5> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics5>
    {
        int32_t __stdcall get_LightsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LightsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipPlacementModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipPlacementModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusKeyboardNavigationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusKeyboardNavigationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighContrastAdjustmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HighContrastAdjustmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TabFocusNavigationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TabFocusNavigationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics6> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics6>
    {
        int32_t __stdcall get_GettingFocusEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().GettingFocusEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LosingFocusEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().LosingFocusEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NoFocusCandidateFoundEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().NoFocusCandidateFoundEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics7> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics7>
    {
        int32_t __stdcall get_PreviewKeyDownEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PreviewKeyDownEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterReceivedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().CharacterReceivedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviewKeyUpEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().PreviewKeyUpEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics8> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics8>
    {
        int32_t __stdcall get_BringIntoViewRequestedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().BringIntoViewRequestedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContextRequestedEvent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::RoutedEvent>(this->shim().ContextRequestedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyboardAcceleratorPlacementTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyboardAcceleratorPlacementTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyboardAcceleratorPlacementModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyboardAcceleratorPlacementModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAsScrollPort(void* element) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterAsScrollPort(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementStatics9> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementStatics9>
    {
        int32_t __stdcall get_CanBeScrollAnchorProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CanBeScrollAnchorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementWeakCollection> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementWeakCollection>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUIElementWeakCollectionFactory> : produce_base<D, winrt::Windows::UI::Xaml::IUIElementWeakCollectionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElementWeakCollection>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs>
    {
        int32_t __stdcall get_Exception(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().Exception());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVector3Transition> : produce_base<D, winrt::Windows::UI::Xaml::IVector3Transition>
    {
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Components(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Vector3TransitionComponents>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Components(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Components(*reinterpret_cast<winrt::Windows::UI::Xaml::Vector3TransitionComponents const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVector3TransitionFactory> : produce_base<D, winrt::Windows::UI::Xaml::IVector3TransitionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Vector3Transition>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualState> : produce_base<D, winrt::Windows::UI::Xaml::IVisualState>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Storyboard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::Storyboard>(this->shim().Storyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Storyboard(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Storyboard(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Storyboard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualState2> : produce_base<D, winrt::Windows::UI::Xaml::IVisualState2>
    {
        int32_t __stdcall get_Setters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::SetterBaseCollection>(this->shim().Setters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StateTriggers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::StateTriggerBase>>(this->shim().StateTriggers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs>
    {
        int32_t __stdcall get_OldState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VisualState>(this->shim().OldState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OldState(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OldState(*reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VisualState>(this->shim().NewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NewState(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NewState(*reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Control>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Control(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Control(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Control const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateGroup> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateGroup>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Transitions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualTransition>>(this->shim().Transitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_States(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualState>>(this->shim().States());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VisualState>(this->shim().CurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CurrentStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentStateChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CurrentStateChanging(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentStateChanging(*reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentStateChanging(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentStateChanging(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateManager> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateManager>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateManagerFactory> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateManagerFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VisualStateManager>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateManagerOverrides> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateManagerOverrides>
    {
        int32_t __stdcall GoToStateCore(void* control, void* templateRoot, void* stateName, void* group, void* state, bool useTransitions, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GoToStateCore(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Control const*>(&control), *reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&templateRoot), *reinterpret_cast<hstring const*>(&stateName), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateGroup const*>(&group), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&state), useTransitions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateManagerProtected> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateManagerProtected>
    {
        int32_t __stdcall RaiseCurrentStateChanging(void* stateGroup, void* oldState, void* newState, void* control) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaiseCurrentStateChanging(*reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateGroup const*>(&stateGroup), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&oldState), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&newState), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Control const*>(&control));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RaiseCurrentStateChanged(void* stateGroup, void* oldState, void* newState, void* control) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaiseCurrentStateChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateGroup const*>(&stateGroup), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&oldState), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualState const*>(&newState), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Control const*>(&control));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualStateManagerStatics> : produce_base<D, winrt::Windows::UI::Xaml::IVisualStateManagerStatics>
    {
        int32_t __stdcall GetVisualStateGroups(void* obj, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::VisualStateGroup>>(this->shim().GetVisualStateGroups(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&obj)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVisualStateManagerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CustomVisualStateManagerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCustomVisualStateManager(void* obj, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::VisualStateManager>(this->shim().GetCustomVisualStateManager(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&obj)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetCustomVisualStateManager(void* obj, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCustomVisualStateManager(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&obj), *reinterpret_cast<winrt::Windows::UI::Xaml::VisualStateManager const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GoToState(void* control, void* stateName, bool useTransitions, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GoToState(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Control const*>(&control), *reinterpret_cast<hstring const*>(&stateName), useTransitions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualTransition> : produce_base<D, winrt::Windows::UI::Xaml::IVisualTransition>
    {
        int32_t __stdcall get_GeneratedDuration(struct struct_Windows_UI_Xaml_Duration* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().GeneratedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GeneratedDuration(struct struct_Windows_UI_Xaml_Duration value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GeneratedDuration(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GeneratedEasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().GeneratedEasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GeneratedEasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GeneratedEasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_To(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_To(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().To(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_From(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_From(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().From(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Storyboard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::Storyboard>(this->shim().Storyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Storyboard(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Storyboard(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Storyboard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IVisualTransitionFactory> : produce_base<D, winrt::Windows::UI::Xaml::IVisualTransitionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VisualTransition>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IWindow> : produce_base<D, winrt::Windows::UI::Xaml::IWindow>
    {
        int32_t __stdcall get_Bounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Visible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Content(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Content(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CoreWindow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreWindow>(this->shim().CoreWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Dispatcher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Activated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<winrt::Windows::UI::Xaml::WindowActivatedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Activated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::UI::Xaml::WindowClosedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SizeChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::WindowSizeChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SizeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VisibilityChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VisibilityChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::WindowVisibilityChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VisibilityChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Activate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Activate();
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
    struct produce<D, winrt::Windows::UI::Xaml::IWindow2> : produce_base<D, winrt::Windows::UI::Xaml::IWindow2>
    {
        int32_t __stdcall SetTitleBar(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTitleBar(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IWindow3> : produce_base<D, winrt::Windows::UI::Xaml::IWindow3>
    {
        int32_t __stdcall get_Compositor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IWindow4> : produce_base<D, winrt::Windows::UI::Xaml::IWindow4>
    {
        int32_t __stdcall get_UIContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IWindowCreatedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IWindowCreatedEventArgs>
    {
        int32_t __stdcall get_Window(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Window>(this->shim().Window());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IWindowStatics> : produce_base<D, winrt::Windows::UI::Xaml::IWindowStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Window>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IXamlRoot> : produce_base<D, winrt::Windows::UI::Xaml::IXamlRoot>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Size(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RasterizationScale(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RasterizationScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHostVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHostVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UIContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::XamlRoot, winrt::Windows::UI::Xaml::XamlRootChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::IXamlRootChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::IXamlRootChangedEventArgs>
    {
    };
#endif
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IApplicationOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IApplicationOverrides>
{
    auto OnActivated(winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnActivated(args);
        }

        return this->shim().OnActivated(args);
    }
    auto OnLaunched(winrt::Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnLaunched(args);
        }

        return this->shim().OnLaunched(args);
    }
    auto OnFileActivated(winrt::Windows::ApplicationModel::Activation::FileActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnFileActivated(args);
        }

        return this->shim().OnFileActivated(args);
    }
    auto OnSearchActivated(winrt::Windows::ApplicationModel::Activation::SearchActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnSearchActivated(args);
        }

        return this->shim().OnSearchActivated(args);
    }
    auto OnShareTargetActivated(winrt::Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnShareTargetActivated(args);
        }

        return this->shim().OnShareTargetActivated(args);
    }
    auto OnFileOpenPickerActivated(winrt::Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnFileOpenPickerActivated(args);
        }

        return this->shim().OnFileOpenPickerActivated(args);
    }
    auto OnFileSavePickerActivated(winrt::Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnFileSavePickerActivated(args);
        }

        return this->shim().OnFileSavePickerActivated(args);
    }
    auto OnCachedFileUpdaterActivated(winrt::Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnCachedFileUpdaterActivated(args);
        }

        return this->shim().OnCachedFileUpdaterActivated(args);
    }
    auto OnWindowCreated(winrt::Windows::UI::Xaml::WindowCreatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnWindowCreated(args);
        }

        return this->shim().OnWindowCreated(args);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IApplicationOverrides2>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IApplicationOverrides2>
{
    auto OnBackgroundActivated(winrt::Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnBackgroundActivated(args);
        }

        return this->shim().OnBackgroundActivated(args);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides>
{
    auto MeasureOverride(winrt::Windows::Foundation::Size const& availableSize)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.MeasureOverride(availableSize);
        }

        return this->shim().MeasureOverride(availableSize);
    }
    auto ArrangeOverride(winrt::Windows::Foundation::Size const& finalSize)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.ArrangeOverride(finalSize);
        }

        return this->shim().ArrangeOverride(finalSize);
    }
    auto OnApplyTemplate()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnApplyTemplate();
        }

        return this->shim().OnApplyTemplate();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2>
{
    auto GoToElementStateCore(hstring const& stateName, bool useTransitions)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GoToElementStateCore(stateName, useTransitions);
        }

        return this->shim().GoToElementStateCore(stateName, useTransitions);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides>
{
    auto OnCreateAutomationPeer()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnCreateAutomationPeer();
        }

        return this->shim().OnCreateAutomationPeer();
    }
    auto OnDisconnectVisualChildren()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnDisconnectVisualChildren();
        }

        return this->shim().OnDisconnectVisualChildren();
    }
    auto FindSubElementsForTouchTargeting(winrt::Windows::Foundation::Point const& point, winrt::Windows::Foundation::Rect const& boundingRect)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.FindSubElementsForTouchTargeting(point, boundingRect);
        }

        return this->shim().FindSubElementsForTouchTargeting(point, boundingRect);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides7>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides7>
{
    auto GetChildrenInTabFocusOrder()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetChildrenInTabFocusOrder();
        }

        return this->shim().GetChildrenInTabFocusOrder();
    }
    auto OnProcessKeyboardAccelerators(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnProcessKeyboardAccelerators(args);
        }

        return this->shim().OnProcessKeyboardAccelerators(args);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides8>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides8>
{
    auto OnKeyboardAcceleratorInvoked(winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnKeyboardAcceleratorInvoked(args);
        }

        return this->shim().OnKeyboardAcceleratorInvoked(args);
    }
    auto OnBringIntoViewRequested(winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs const& e)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnBringIntoViewRequested(e);
        }

        return this->shim().OnBringIntoViewRequested(e);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides9>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IUIElementOverrides9>
{
    auto PopulatePropertyInfoOverride(hstring const& propertyName, winrt::Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
        }

        return this->shim().PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::IVisualStateManagerOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::IVisualStateManagerOverrides>
{
    auto GoToStateCore(winrt::Windows::UI::Xaml::Controls::Control const& control, winrt::Windows::UI::Xaml::FrameworkElement const& templateRoot, hstring const& stateName, winrt::Windows::UI::Xaml::VisualStateGroup const& group, winrt::Windows::UI::Xaml::VisualState const& state, bool useTransitions)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GoToStateCore(control, templateRoot, stateName, group, state, useTransitions);
        }

        return this->shim().GoToStateCore(control, templateRoot, stateName, group, state, useTransitions);
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml
{
    constexpr auto operator|(ApplicationHighContrastAdjustment const left, ApplicationHighContrastAdjustment const right) noexcept
    {
        return static_cast<ApplicationHighContrastAdjustment>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ApplicationHighContrastAdjustment& left, ApplicationHighContrastAdjustment const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ApplicationHighContrastAdjustment const left, ApplicationHighContrastAdjustment const right) noexcept
    {
        return static_cast<ApplicationHighContrastAdjustment>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ApplicationHighContrastAdjustment& left, ApplicationHighContrastAdjustment const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ApplicationHighContrastAdjustment const value) noexcept
    {
        return static_cast<ApplicationHighContrastAdjustment>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ApplicationHighContrastAdjustment const left, ApplicationHighContrastAdjustment const right) noexcept
    {
        return static_cast<ApplicationHighContrastAdjustment>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ApplicationHighContrastAdjustment& left, ApplicationHighContrastAdjustment const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(ElementHighContrastAdjustment const left, ElementHighContrastAdjustment const right) noexcept
    {
        return static_cast<ElementHighContrastAdjustment>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ElementHighContrastAdjustment& left, ElementHighContrastAdjustment const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ElementHighContrastAdjustment const left, ElementHighContrastAdjustment const right) noexcept
    {
        return static_cast<ElementHighContrastAdjustment>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ElementHighContrastAdjustment& left, ElementHighContrastAdjustment const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ElementHighContrastAdjustment const value) noexcept
    {
        return static_cast<ElementHighContrastAdjustment>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ElementHighContrastAdjustment const left, ElementHighContrastAdjustment const right) noexcept
    {
        return static_cast<ElementHighContrastAdjustment>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ElementHighContrastAdjustment& left, ElementHighContrastAdjustment const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(Vector3TransitionComponents const left, Vector3TransitionComponents const right) noexcept
    {
        return static_cast<Vector3TransitionComponents>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(Vector3TransitionComponents& left, Vector3TransitionComponents const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(Vector3TransitionComponents const left, Vector3TransitionComponents const right) noexcept
    {
        return static_cast<Vector3TransitionComponents>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(Vector3TransitionComponents& left, Vector3TransitionComponents const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(Vector3TransitionComponents const value) noexcept
    {
        return static_cast<Vector3TransitionComponents>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(Vector3TransitionComponents const left, Vector3TransitionComponents const right) noexcept
    {
        return static_cast<Vector3TransitionComponents>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(Vector3TransitionComponents& left, Vector3TransitionComponents const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline AdaptiveTrigger::AdaptiveTrigger()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<AdaptiveTrigger, IAdaptiveTriggerFactory>([&](IAdaptiveTriggerFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto AdaptiveTrigger::MinWindowWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IAdaptiveTriggerStatics const&), AdaptiveTrigger, IAdaptiveTriggerStatics>([](IAdaptiveTriggerStatics const& f) { return f.MinWindowWidthProperty(); });
    }
    inline auto AdaptiveTrigger::MinWindowHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IAdaptiveTriggerStatics const&), AdaptiveTrigger, IAdaptiveTriggerStatics>([](IAdaptiveTriggerStatics const& f) { return f.MinWindowHeightProperty(); });
    }
    inline Application::Application()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<Application, IApplicationFactory>([&](IApplicationFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto Application::Current()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Application(*)(IApplicationStatics const&), Application, IApplicationStatics>([](IApplicationStatics const& f) { return f.Current(); });
    }
    inline auto Application::Start(winrt::Windows::UI::Xaml::ApplicationInitializationCallback const& callback)
    {
        impl::call_factory<Application, IApplicationStatics>([&](IApplicationStatics const& f) { return f.Start(callback); });
    }
    inline auto Application::LoadComponent(winrt::Windows::Foundation::IInspectable const& component, winrt::Windows::Foundation::Uri const& resourceLocator)
    {
        impl::call_factory<Application, IApplicationStatics>([&](IApplicationStatics const& f) { return f.LoadComponent(component, resourceLocator); });
    }
    inline auto Application::LoadComponent(winrt::Windows::Foundation::IInspectable const& component, winrt::Windows::Foundation::Uri const& resourceLocator, winrt::Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const& componentResourceLocation)
    {
        impl::call_factory<Application, IApplicationStatics>([&](IApplicationStatics const& f) { return f.LoadComponent(component, resourceLocator, componentResourceLocation); });
    }
    inline BringIntoViewOptions::BringIntoViewOptions() :
        BringIntoViewOptions(impl::call_factory_cast<BringIntoViewOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), BringIntoViewOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BringIntoViewOptions>(); }))
    {
    }
    inline BrushTransition::BrushTransition()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<BrushTransition, IBrushTransitionFactory>([&](IBrushTransitionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline ColorPaletteResources::ColorPaletteResources()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ColorPaletteResources, IColorPaletteResourcesFactory>([&](IColorPaletteResourcesFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto CornerRadiusHelper::FromRadii(double topLeft, double topRight, double bottomRight, double bottomLeft)
    {
        return impl::call_factory<CornerRadiusHelper, ICornerRadiusHelperStatics>([&](ICornerRadiusHelperStatics const& f) { return f.FromRadii(topLeft, topRight, bottomRight, bottomLeft); });
    }
    inline auto CornerRadiusHelper::FromUniformRadius(double uniformRadius)
    {
        return impl::call_factory<CornerRadiusHelper, ICornerRadiusHelperStatics>([&](ICornerRadiusHelperStatics const& f) { return f.FromUniformRadius(uniformRadius); });
    }
    inline DataTemplate::DataTemplate()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DataTemplate, IDataTemplateFactory>([&](IDataTemplateFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto DataTemplate::ExtensionInstanceProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDataTemplateStatics2 const&), DataTemplate, IDataTemplateStatics2>([](IDataTemplateStatics2 const& f) { return f.ExtensionInstanceProperty(); });
    }
    inline auto DataTemplate::GetExtensionInstance(winrt::Windows::UI::Xaml::FrameworkElement const& element)
    {
        return impl::call_factory<DataTemplate, IDataTemplateStatics2>([&](IDataTemplateStatics2 const& f) { return f.GetExtensionInstance(element); });
    }
    inline auto DataTemplate::SetExtensionInstance(winrt::Windows::UI::Xaml::FrameworkElement const& element, winrt::Windows::UI::Xaml::IDataTemplateExtension const& value)
    {
        impl::call_factory<DataTemplate, IDataTemplateStatics2>([&](IDataTemplateStatics2 const& f) { return f.SetExtensionInstance(element, value); });
    }
    inline DataTemplateKey::DataTemplateKey()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DataTemplateKey, IDataTemplateKeyFactory>([&](IDataTemplateKeyFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline DataTemplateKey::DataTemplateKey(winrt::Windows::Foundation::IInspectable const& dataType)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DataTemplateKey, IDataTemplateKeyFactory>([&](IDataTemplateKeyFactory const& f) { return f.CreateInstanceWithType(dataType, baseInterface, innerInterface); });
    }
    inline DependencyObjectCollection::DependencyObjectCollection()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DependencyObjectCollection, IDependencyObjectCollectionFactory>([&](IDependencyObjectCollectionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto DependencyProperty::UnsetValue()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IInspectable(*)(IDependencyPropertyStatics const&), DependencyProperty, IDependencyPropertyStatics>([](IDependencyPropertyStatics const& f) { return f.UnsetValue(); });
    }
    inline auto DependencyProperty::Register(param::hstring const& name, winrt::Windows::UI::Xaml::Interop::TypeName const& propertyType, winrt::Windows::UI::Xaml::Interop::TypeName const& ownerType, winrt::Windows::UI::Xaml::PropertyMetadata const& typeMetadata)
    {
        return impl::call_factory<DependencyProperty, IDependencyPropertyStatics>([&](IDependencyPropertyStatics const& f) { return f.Register(name, propertyType, ownerType, typeMetadata); });
    }
    inline auto DependencyProperty::RegisterAttached(param::hstring const& name, winrt::Windows::UI::Xaml::Interop::TypeName const& propertyType, winrt::Windows::UI::Xaml::Interop::TypeName const& ownerType, winrt::Windows::UI::Xaml::PropertyMetadata const& defaultMetadata)
    {
        return impl::call_factory<DependencyProperty, IDependencyPropertyStatics>([&](IDependencyPropertyStatics const& f) { return f.RegisterAttached(name, propertyType, ownerType, defaultMetadata); });
    }
    inline DispatcherTimer::DispatcherTimer()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DispatcherTimer, IDispatcherTimerFactory>([&](IDispatcherTimerFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto DurationHelper::Automatic()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Duration(*)(IDurationHelperStatics const&), DurationHelper, IDurationHelperStatics>([](IDurationHelperStatics const& f) { return f.Automatic(); });
    }
    inline auto DurationHelper::Forever()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Duration(*)(IDurationHelperStatics const&), DurationHelper, IDurationHelperStatics>([](IDurationHelperStatics const& f) { return f.Forever(); });
    }
    inline auto DurationHelper::Compare(winrt::Windows::UI::Xaml::Duration const& duration1, winrt::Windows::UI::Xaml::Duration const& duration2)
    {
        return impl::call_factory<DurationHelper, IDurationHelperStatics>([&](IDurationHelperStatics const& f) { return f.Compare(duration1, duration2); });
    }
    inline auto DurationHelper::FromTimeSpan(winrt::Windows::Foundation::TimeSpan const& timeSpan)
    {
        return impl::call_factory<DurationHelper, IDurationHelperStatics>([&](IDurationHelperStatics const& f) { return f.FromTimeSpan(timeSpan); });
    }
    inline auto DurationHelper::GetHasTimeSpan(winrt::Windows::UI::Xaml::Duration const& target)
    {
        return impl::call_factory<DurationHelper, IDurationHelperStatics>([&](IDurationHelperStatics const& f) { return f.GetHasTimeSpan(target); });
    }
    inline auto DurationHelper::Add(winrt::Windows::UI::Xaml::Duration const& target, winrt::Windows::UI::Xaml::Duration const& duration)
    {
        return impl::call_factory<DurationHelper, IDurationHelperStatics>([&](IDurationHelperStatics const& f) { return f.Add(target, duration); });
    }
    inline auto DurationHelper::Equals(winrt::Windows::UI::Xaml::Duration const& target, winrt::Windows::UI::Xaml::Duration const& value)
    {
        return impl::call_factory<DurationHelper, IDurationHelperStatics>([&](IDurationHelperStatics const& f) { return f.Equals(target, value); });
    }
    inline auto DurationHelper::Subtract(winrt::Windows::UI::Xaml::Duration const& target, winrt::Windows::UI::Xaml::Duration const& duration)
    {
        return impl::call_factory<DurationHelper, IDurationHelperStatics>([&](IDurationHelperStatics const& f) { return f.Subtract(target, duration); });
    }
    inline ElementFactoryGetArgs::ElementFactoryGetArgs()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ElementFactoryGetArgs, IElementFactoryGetArgsFactory>([&](IElementFactoryGetArgsFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline ElementFactoryRecycleArgs::ElementFactoryRecycleArgs()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ElementFactoryRecycleArgs, IElementFactoryRecycleArgsFactory>([&](IElementFactoryRecycleArgsFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto ElementSoundPlayer::Volume()
    {
        return impl::call_factory_cast<double(*)(IElementSoundPlayerStatics const&), ElementSoundPlayer, IElementSoundPlayerStatics>([](IElementSoundPlayerStatics const& f) { return f.Volume(); });
    }
    inline auto ElementSoundPlayer::Volume(double value)
    {
        impl::call_factory<ElementSoundPlayer, IElementSoundPlayerStatics>([&](IElementSoundPlayerStatics const& f) { return f.Volume(value); });
    }
    inline auto ElementSoundPlayer::State()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::ElementSoundPlayerState(*)(IElementSoundPlayerStatics const&), ElementSoundPlayer, IElementSoundPlayerStatics>([](IElementSoundPlayerStatics const& f) { return f.State(); });
    }
    inline auto ElementSoundPlayer::State(winrt::Windows::UI::Xaml::ElementSoundPlayerState const& value)
    {
        impl::call_factory<ElementSoundPlayer, IElementSoundPlayerStatics>([&](IElementSoundPlayerStatics const& f) { return f.State(value); });
    }
    inline auto ElementSoundPlayer::Play(winrt::Windows::UI::Xaml::ElementSoundKind const& sound)
    {
        impl::call_factory<ElementSoundPlayer, IElementSoundPlayerStatics>([&](IElementSoundPlayerStatics const& f) { return f.Play(sound); });
    }
    inline auto ElementSoundPlayer::SpatialAudioMode()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::ElementSpatialAudioMode(*)(IElementSoundPlayerStatics2 const&), ElementSoundPlayer, IElementSoundPlayerStatics2>([](IElementSoundPlayerStatics2 const& f) { return f.SpatialAudioMode(); });
    }
    inline auto ElementSoundPlayer::SpatialAudioMode(winrt::Windows::UI::Xaml::ElementSpatialAudioMode const& value)
    {
        impl::call_factory<ElementSoundPlayer, IElementSoundPlayerStatics2>([&](IElementSoundPlayerStatics2 const& f) { return f.SpatialAudioMode(value); });
    }
    inline EventTrigger::EventTrigger() :
        EventTrigger(impl::call_factory_cast<EventTrigger(*)(winrt::Windows::Foundation::IActivationFactory const&), EventTrigger>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EventTrigger>(); }))
    {
    }
    inline auto FrameworkElement::TagProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.TagProperty(); });
    }
    inline auto FrameworkElement::LanguageProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.LanguageProperty(); });
    }
    inline auto FrameworkElement::ActualWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.ActualWidthProperty(); });
    }
    inline auto FrameworkElement::ActualHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.ActualHeightProperty(); });
    }
    inline auto FrameworkElement::WidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.WidthProperty(); });
    }
    inline auto FrameworkElement::HeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.HeightProperty(); });
    }
    inline auto FrameworkElement::MinWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.MinWidthProperty(); });
    }
    inline auto FrameworkElement::MaxWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.MaxWidthProperty(); });
    }
    inline auto FrameworkElement::MinHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.MinHeightProperty(); });
    }
    inline auto FrameworkElement::MaxHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.MaxHeightProperty(); });
    }
    inline auto FrameworkElement::HorizontalAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.HorizontalAlignmentProperty(); });
    }
    inline auto FrameworkElement::VerticalAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.VerticalAlignmentProperty(); });
    }
    inline auto FrameworkElement::MarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.MarginProperty(); });
    }
    inline auto FrameworkElement::NameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.NameProperty(); });
    }
    inline auto FrameworkElement::DataContextProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.DataContextProperty(); });
    }
    inline auto FrameworkElement::StyleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.StyleProperty(); });
    }
    inline auto FrameworkElement::FlowDirectionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics const&), FrameworkElement, IFrameworkElementStatics>([](IFrameworkElementStatics const& f) { return f.FlowDirectionProperty(); });
    }
    inline auto FrameworkElement::RequestedThemeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics2 const&), FrameworkElement, IFrameworkElementStatics2>([](IFrameworkElementStatics2 const& f) { return f.RequestedThemeProperty(); });
    }
    inline auto FrameworkElement::AllowFocusOnInteractionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.AllowFocusOnInteractionProperty(); });
    }
    inline auto FrameworkElement::FocusVisualMarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.FocusVisualMarginProperty(); });
    }
    inline auto FrameworkElement::FocusVisualSecondaryThicknessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.FocusVisualSecondaryThicknessProperty(); });
    }
    inline auto FrameworkElement::FocusVisualPrimaryThicknessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.FocusVisualPrimaryThicknessProperty(); });
    }
    inline auto FrameworkElement::FocusVisualSecondaryBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.FocusVisualSecondaryBrushProperty(); });
    }
    inline auto FrameworkElement::FocusVisualPrimaryBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.FocusVisualPrimaryBrushProperty(); });
    }
    inline auto FrameworkElement::AllowFocusWhenDisabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics4 const&), FrameworkElement, IFrameworkElementStatics4>([](IFrameworkElementStatics4 const& f) { return f.AllowFocusWhenDisabledProperty(); });
    }
    inline auto FrameworkElement::DeferTree(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        impl::call_factory<FrameworkElement, IFrameworkElementStatics5>([&](IFrameworkElementStatics5 const& f) { return f.DeferTree(element); });
    }
    inline auto FrameworkElement::ActualThemeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFrameworkElementStatics6 const&), FrameworkElement, IFrameworkElementStatics6>([](IFrameworkElementStatics6 const& f) { return f.ActualThemeProperty(); });
    }
    inline FrameworkView::FrameworkView() :
        FrameworkView(impl::call_factory_cast<FrameworkView(*)(winrt::Windows::Foundation::IActivationFactory const&), FrameworkView>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FrameworkView>(); }))
    {
    }
    inline FrameworkViewSource::FrameworkViewSource() :
        FrameworkViewSource(impl::call_factory_cast<FrameworkViewSource(*)(winrt::Windows::Foundation::IActivationFactory const&), FrameworkViewSource>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FrameworkViewSource>(); }))
    {
    }
    inline auto GridLengthHelper::Auto()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::GridLength(*)(IGridLengthHelperStatics const&), GridLengthHelper, IGridLengthHelperStatics>([](IGridLengthHelperStatics const& f) { return f.Auto(); });
    }
    inline auto GridLengthHelper::FromPixels(double pixels)
    {
        return impl::call_factory<GridLengthHelper, IGridLengthHelperStatics>([&](IGridLengthHelperStatics const& f) { return f.FromPixels(pixels); });
    }
    inline auto GridLengthHelper::FromValueAndType(double value, winrt::Windows::UI::Xaml::GridUnitType const& type)
    {
        return impl::call_factory<GridLengthHelper, IGridLengthHelperStatics>([&](IGridLengthHelperStatics const& f) { return f.FromValueAndType(value, type); });
    }
    inline auto GridLengthHelper::GetIsAbsolute(winrt::Windows::UI::Xaml::GridLength const& target)
    {
        return impl::call_factory<GridLengthHelper, IGridLengthHelperStatics>([&](IGridLengthHelperStatics const& f) { return f.GetIsAbsolute(target); });
    }
    inline auto GridLengthHelper::GetIsAuto(winrt::Windows::UI::Xaml::GridLength const& target)
    {
        return impl::call_factory<GridLengthHelper, IGridLengthHelperStatics>([&](IGridLengthHelperStatics const& f) { return f.GetIsAuto(target); });
    }
    inline auto GridLengthHelper::GetIsStar(winrt::Windows::UI::Xaml::GridLength const& target)
    {
        return impl::call_factory<GridLengthHelper, IGridLengthHelperStatics>([&](IGridLengthHelperStatics const& f) { return f.GetIsStar(target); });
    }
    inline auto GridLengthHelper::Equals(winrt::Windows::UI::Xaml::GridLength const& target, winrt::Windows::UI::Xaml::GridLength const& value)
    {
        return impl::call_factory<GridLengthHelper, IGridLengthHelperStatics>([&](IGridLengthHelperStatics const& f) { return f.Equals(target, value); });
    }
    inline auto PointHelper::FromCoordinates(float x, float y)
    {
        return impl::call_factory<PointHelper, IPointHelperStatics>([&](IPointHelperStatics const& f) { return f.FromCoordinates(x, y); });
    }
    inline PropertyMetadata::PropertyMetadata(winrt::Windows::Foundation::IInspectable const& defaultValue)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<PropertyMetadata, IPropertyMetadataFactory>([&](IPropertyMetadataFactory const& f) { return f.CreateInstanceWithDefaultValue(defaultValue, baseInterface, innerInterface); });
    }
    inline PropertyMetadata::PropertyMetadata(winrt::Windows::Foundation::IInspectable const& defaultValue, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<PropertyMetadata, IPropertyMetadataFactory>([&](IPropertyMetadataFactory const& f) { return f.CreateInstanceWithDefaultValueAndCallback(defaultValue, propertyChangedCallback, baseInterface, innerInterface); });
    }
    inline auto PropertyMetadata::Create(winrt::Windows::Foundation::IInspectable const& defaultValue)
    {
        return impl::call_factory<PropertyMetadata, IPropertyMetadataStatics>([&](IPropertyMetadataStatics const& f) { return f.Create(defaultValue); });
    }
    inline auto PropertyMetadata::Create(winrt::Windows::Foundation::IInspectable const& defaultValue, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
    {
        return impl::call_factory<PropertyMetadata, IPropertyMetadataStatics>([&](IPropertyMetadataStatics const& f) { return f.Create(defaultValue, propertyChangedCallback); });
    }
    inline auto PropertyMetadata::Create(winrt::Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback)
    {
        return impl::call_factory<PropertyMetadata, IPropertyMetadataStatics>([&](IPropertyMetadataStatics const& f) { return f.Create(createDefaultValueCallback); });
    }
    inline auto PropertyMetadata::Create(winrt::Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
    {
        return impl::call_factory<PropertyMetadata, IPropertyMetadataStatics>([&](IPropertyMetadataStatics const& f) { return f.Create(createDefaultValueCallback, propertyChangedCallback); });
    }
    inline PropertyPath::PropertyPath(param::hstring const& path) :
        PropertyPath(impl::call_factory<PropertyPath, IPropertyPathFactory>([&](IPropertyPathFactory const& f) { return f.CreateInstance(path); }))
    {
    }
    inline auto RectHelper::Empty()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Rect(*)(IRectHelperStatics const&), RectHelper, IRectHelperStatics>([](IRectHelperStatics const& f) { return f.Empty(); });
    }
    inline auto RectHelper::FromCoordinatesAndDimensions(float x, float y, float width, float height)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.FromCoordinatesAndDimensions(x, y, width, height); });
    }
    inline auto RectHelper::FromPoints(winrt::Windows::Foundation::Point const& point1, winrt::Windows::Foundation::Point const& point2)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.FromPoints(point1, point2); });
    }
    inline auto RectHelper::FromLocationAndSize(winrt::Windows::Foundation::Point const& location, winrt::Windows::Foundation::Size const& size)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.FromLocationAndSize(location, size); });
    }
    inline auto RectHelper::GetIsEmpty(winrt::Windows::Foundation::Rect const& target)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.GetIsEmpty(target); });
    }
    inline auto RectHelper::GetBottom(winrt::Windows::Foundation::Rect const& target)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.GetBottom(target); });
    }
    inline auto RectHelper::GetLeft(winrt::Windows::Foundation::Rect const& target)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.GetLeft(target); });
    }
    inline auto RectHelper::GetRight(winrt::Windows::Foundation::Rect const& target)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.GetRight(target); });
    }
    inline auto RectHelper::GetTop(winrt::Windows::Foundation::Rect const& target)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.GetTop(target); });
    }
    inline auto RectHelper::Contains(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Point const& point)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.Contains(target, point); });
    }
    inline auto RectHelper::Equals(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Rect const& value)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.Equals(target, value); });
    }
    inline auto RectHelper::Intersect(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Rect const& rect)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.Intersect(target, rect); });
    }
    inline auto RectHelper::Union(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Point const& point)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.Union(target, point); });
    }
    inline auto RectHelper::Union(winrt::Windows::Foundation::Rect const& target, winrt::Windows::Foundation::Rect const& rect)
    {
        return impl::call_factory<RectHelper, IRectHelperStatics>([&](IRectHelperStatics const& f) { return f.Union(target, rect); });
    }
    inline ResourceDictionary::ResourceDictionary()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ResourceDictionary, IResourceDictionaryFactory>([&](IResourceDictionaryFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline RoutedEventArgs::RoutedEventArgs()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RoutedEventArgs, IRoutedEventArgsFactory>([&](IRoutedEventArgsFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline ScalarTransition::ScalarTransition()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ScalarTransition, IScalarTransitionFactory>([&](IScalarTransitionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline Setter::Setter() :
        Setter(impl::call_factory_cast<Setter(*)(winrt::Windows::Foundation::IActivationFactory const&), Setter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Setter>(); }))
    {
    }
    inline Setter::Setter(winrt::Windows::UI::Xaml::DependencyProperty const& targetProperty, winrt::Windows::Foundation::IInspectable const& value) :
        Setter(impl::call_factory<Setter, ISetterFactory>([&](ISetterFactory const& f) { return f.CreateInstance(targetProperty, value); }))
    {
    }
    inline SetterBaseCollection::SetterBaseCollection() :
        SetterBaseCollection(impl::call_factory_cast<SetterBaseCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), SetterBaseCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SetterBaseCollection>(); }))
    {
    }
    inline auto SizeHelper::Empty()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Size(*)(ISizeHelperStatics const&), SizeHelper, ISizeHelperStatics>([](ISizeHelperStatics const& f) { return f.Empty(); });
    }
    inline auto SizeHelper::FromDimensions(float width, float height)
    {
        return impl::call_factory<SizeHelper, ISizeHelperStatics>([&](ISizeHelperStatics const& f) { return f.FromDimensions(width, height); });
    }
    inline auto SizeHelper::GetIsEmpty(winrt::Windows::Foundation::Size const& target)
    {
        return impl::call_factory<SizeHelper, ISizeHelperStatics>([&](ISizeHelperStatics const& f) { return f.GetIsEmpty(target); });
    }
    inline auto SizeHelper::Equals(winrt::Windows::Foundation::Size const& target, winrt::Windows::Foundation::Size const& value)
    {
        return impl::call_factory<SizeHelper, ISizeHelperStatics>([&](ISizeHelperStatics const& f) { return f.Equals(target, value); });
    }
    inline StateTrigger::StateTrigger() :
        StateTrigger(impl::call_factory_cast<StateTrigger(*)(winrt::Windows::Foundation::IActivationFactory const&), StateTrigger>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StateTrigger>(); }))
    {
    }
    inline auto StateTrigger::IsActiveProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IStateTriggerStatics const&), StateTrigger, IStateTriggerStatics>([](IStateTriggerStatics const& f) { return f.IsActiveProperty(); });
    }
    inline Style::Style() :
        Style(impl::call_factory_cast<Style(*)(winrt::Windows::Foundation::IActivationFactory const&), Style>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Style>(); }))
    {
    }
    inline Style::Style(winrt::Windows::UI::Xaml::Interop::TypeName const& targetType) :
        Style(impl::call_factory<Style, IStyleFactory>([&](IStyleFactory const& f) { return f.CreateInstance(targetType); }))
    {
    }
    inline TargetPropertyPath::TargetPropertyPath() :
        TargetPropertyPath(impl::call_factory_cast<TargetPropertyPath(*)(winrt::Windows::Foundation::IActivationFactory const&), TargetPropertyPath>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TargetPropertyPath>(); }))
    {
    }
    inline TargetPropertyPath::TargetPropertyPath(winrt::Windows::UI::Xaml::DependencyProperty const& targetProperty) :
        TargetPropertyPath(impl::call_factory<TargetPropertyPath, ITargetPropertyPathFactory>([&](ITargetPropertyPathFactory const& f) { return f.CreateInstance(targetProperty); }))
    {
    }
    inline auto ThicknessHelper::FromLengths(double left, double top, double right, double bottom)
    {
        return impl::call_factory<ThicknessHelper, IThicknessHelperStatics>([&](IThicknessHelperStatics const& f) { return f.FromLengths(left, top, right, bottom); });
    }
    inline auto ThicknessHelper::FromUniformLength(double uniformLength)
    {
        return impl::call_factory<ThicknessHelper, IThicknessHelperStatics>([&](IThicknessHelperStatics const& f) { return f.FromUniformLength(uniformLength); });
    }
    inline TriggerActionCollection::TriggerActionCollection() :
        TriggerActionCollection(impl::call_factory_cast<TriggerActionCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), TriggerActionCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TriggerActionCollection>(); }))
    {
    }
    inline auto UIElement::KeyDownEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.KeyDownEvent(); });
    }
    inline auto UIElement::KeyUpEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.KeyUpEvent(); });
    }
    inline auto UIElement::PointerEnteredEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerEnteredEvent(); });
    }
    inline auto UIElement::PointerPressedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerPressedEvent(); });
    }
    inline auto UIElement::PointerMovedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerMovedEvent(); });
    }
    inline auto UIElement::PointerReleasedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerReleasedEvent(); });
    }
    inline auto UIElement::PointerExitedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerExitedEvent(); });
    }
    inline auto UIElement::PointerCaptureLostEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerCaptureLostEvent(); });
    }
    inline auto UIElement::PointerCanceledEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerCanceledEvent(); });
    }
    inline auto UIElement::PointerWheelChangedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerWheelChangedEvent(); });
    }
    inline auto UIElement::TappedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.TappedEvent(); });
    }
    inline auto UIElement::DoubleTappedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.DoubleTappedEvent(); });
    }
    inline auto UIElement::HoldingEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.HoldingEvent(); });
    }
    inline auto UIElement::RightTappedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.RightTappedEvent(); });
    }
    inline auto UIElement::ManipulationStartingEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ManipulationStartingEvent(); });
    }
    inline auto UIElement::ManipulationInertiaStartingEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ManipulationInertiaStartingEvent(); });
    }
    inline auto UIElement::ManipulationStartedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ManipulationStartedEvent(); });
    }
    inline auto UIElement::ManipulationDeltaEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ManipulationDeltaEvent(); });
    }
    inline auto UIElement::ManipulationCompletedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ManipulationCompletedEvent(); });
    }
    inline auto UIElement::DragEnterEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.DragEnterEvent(); });
    }
    inline auto UIElement::DragLeaveEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.DragLeaveEvent(); });
    }
    inline auto UIElement::DragOverEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.DragOverEvent(); });
    }
    inline auto UIElement::DropEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.DropEvent(); });
    }
    inline auto UIElement::AllowDropProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.AllowDropProperty(); });
    }
    inline auto UIElement::OpacityProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.OpacityProperty(); });
    }
    inline auto UIElement::ClipProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ClipProperty(); });
    }
    inline auto UIElement::RenderTransformProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.RenderTransformProperty(); });
    }
    inline auto UIElement::ProjectionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ProjectionProperty(); });
    }
    inline auto UIElement::RenderTransformOriginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.RenderTransformOriginProperty(); });
    }
    inline auto UIElement::IsHitTestVisibleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.IsHitTestVisibleProperty(); });
    }
    inline auto UIElement::VisibilityProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.VisibilityProperty(); });
    }
    inline auto UIElement::UseLayoutRoundingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.UseLayoutRoundingProperty(); });
    }
    inline auto UIElement::TransitionsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.TransitionsProperty(); });
    }
    inline auto UIElement::CacheModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.CacheModeProperty(); });
    }
    inline auto UIElement::IsTapEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.IsTapEnabledProperty(); });
    }
    inline auto UIElement::IsDoubleTapEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.IsDoubleTapEnabledProperty(); });
    }
    inline auto UIElement::IsRightTapEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.IsRightTapEnabledProperty(); });
    }
    inline auto UIElement::IsHoldingEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.IsHoldingEnabledProperty(); });
    }
    inline auto UIElement::ManipulationModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.ManipulationModeProperty(); });
    }
    inline auto UIElement::PointerCapturesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics const&), UIElement, IUIElementStatics>([](IUIElementStatics const& f) { return f.PointerCapturesProperty(); });
    }
    inline auto UIElement::ShadowProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics10 const&), UIElement, IUIElementStatics10>([](IUIElementStatics10 const& f) { return f.ShadowProperty(); });
    }
    inline auto UIElement::CompositeModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics2 const&), UIElement, IUIElementStatics2>([](IUIElementStatics2 const& f) { return f.CompositeModeProperty(); });
    }
    inline auto UIElement::Transform3DProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics3 const&), UIElement, IUIElementStatics3>([](IUIElementStatics3 const& f) { return f.Transform3DProperty(); });
    }
    inline auto UIElement::CanDragProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics3 const&), UIElement, IUIElementStatics3>([](IUIElementStatics3 const& f) { return f.CanDragProperty(); });
    }
    inline auto UIElement::TryStartDirectManipulation(winrt::Windows::UI::Xaml::Input::Pointer const& value)
    {
        return impl::call_factory<UIElement, IUIElementStatics3>([&](IUIElementStatics3 const& f) { return f.TryStartDirectManipulation(value); });
    }
    inline auto UIElement::ContextFlyoutProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics4 const&), UIElement, IUIElementStatics4>([](IUIElementStatics4 const& f) { return f.ContextFlyoutProperty(); });
    }
    inline auto UIElement::ExitDisplayModeOnAccessKeyInvokedProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics4 const&), UIElement, IUIElementStatics4>([](IUIElementStatics4 const& f) { return f.ExitDisplayModeOnAccessKeyInvokedProperty(); });
    }
    inline auto UIElement::IsAccessKeyScopeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics4 const&), UIElement, IUIElementStatics4>([](IUIElementStatics4 const& f) { return f.IsAccessKeyScopeProperty(); });
    }
    inline auto UIElement::AccessKeyScopeOwnerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics4 const&), UIElement, IUIElementStatics4>([](IUIElementStatics4 const& f) { return f.AccessKeyScopeOwnerProperty(); });
    }
    inline auto UIElement::AccessKeyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics4 const&), UIElement, IUIElementStatics4>([](IUIElementStatics4 const& f) { return f.AccessKeyProperty(); });
    }
    inline auto UIElement::LightsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.LightsProperty(); });
    }
    inline auto UIElement::KeyTipPlacementModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.KeyTipPlacementModeProperty(); });
    }
    inline auto UIElement::KeyTipHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.KeyTipHorizontalOffsetProperty(); });
    }
    inline auto UIElement::KeyTipVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.KeyTipVerticalOffsetProperty(); });
    }
    inline auto UIElement::XYFocusKeyboardNavigationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.XYFocusKeyboardNavigationProperty(); });
    }
    inline auto UIElement::XYFocusUpNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.XYFocusUpNavigationStrategyProperty(); });
    }
    inline auto UIElement::XYFocusDownNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.XYFocusDownNavigationStrategyProperty(); });
    }
    inline auto UIElement::XYFocusLeftNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.XYFocusLeftNavigationStrategyProperty(); });
    }
    inline auto UIElement::XYFocusRightNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.XYFocusRightNavigationStrategyProperty(); });
    }
    inline auto UIElement::HighContrastAdjustmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.HighContrastAdjustmentProperty(); });
    }
    inline auto UIElement::TabFocusNavigationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics5 const&), UIElement, IUIElementStatics5>([](IUIElementStatics5 const& f) { return f.TabFocusNavigationProperty(); });
    }
    inline auto UIElement::GettingFocusEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics6 const&), UIElement, IUIElementStatics6>([](IUIElementStatics6 const& f) { return f.GettingFocusEvent(); });
    }
    inline auto UIElement::LosingFocusEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics6 const&), UIElement, IUIElementStatics6>([](IUIElementStatics6 const& f) { return f.LosingFocusEvent(); });
    }
    inline auto UIElement::NoFocusCandidateFoundEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics6 const&), UIElement, IUIElementStatics6>([](IUIElementStatics6 const& f) { return f.NoFocusCandidateFoundEvent(); });
    }
    inline auto UIElement::PreviewKeyDownEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics7 const&), UIElement, IUIElementStatics7>([](IUIElementStatics7 const& f) { return f.PreviewKeyDownEvent(); });
    }
    inline auto UIElement::CharacterReceivedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics7 const&), UIElement, IUIElementStatics7>([](IUIElementStatics7 const& f) { return f.CharacterReceivedEvent(); });
    }
    inline auto UIElement::PreviewKeyUpEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics7 const&), UIElement, IUIElementStatics7>([](IUIElementStatics7 const& f) { return f.PreviewKeyUpEvent(); });
    }
    inline auto UIElement::BringIntoViewRequestedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics8 const&), UIElement, IUIElementStatics8>([](IUIElementStatics8 const& f) { return f.BringIntoViewRequestedEvent(); });
    }
    inline auto UIElement::ContextRequestedEvent()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::RoutedEvent(*)(IUIElementStatics8 const&), UIElement, IUIElementStatics8>([](IUIElementStatics8 const& f) { return f.ContextRequestedEvent(); });
    }
    inline auto UIElement::KeyTipTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics8 const&), UIElement, IUIElementStatics8>([](IUIElementStatics8 const& f) { return f.KeyTipTargetProperty(); });
    }
    inline auto UIElement::KeyboardAcceleratorPlacementTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics8 const&), UIElement, IUIElementStatics8>([](IUIElementStatics8 const& f) { return f.KeyboardAcceleratorPlacementTargetProperty(); });
    }
    inline auto UIElement::KeyboardAcceleratorPlacementModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics8 const&), UIElement, IUIElementStatics8>([](IUIElementStatics8 const& f) { return f.KeyboardAcceleratorPlacementModeProperty(); });
    }
    inline auto UIElement::RegisterAsScrollPort(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        impl::call_factory<UIElement, IUIElementStatics8>([&](IUIElementStatics8 const& f) { return f.RegisterAsScrollPort(element); });
    }
    inline auto UIElement::CanBeScrollAnchorProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IUIElementStatics9 const&), UIElement, IUIElementStatics9>([](IUIElementStatics9 const& f) { return f.CanBeScrollAnchorProperty(); });
    }
    inline UIElementWeakCollection::UIElementWeakCollection()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<UIElementWeakCollection, IUIElementWeakCollectionFactory>([&](IUIElementWeakCollectionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline Vector3Transition::Vector3Transition()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<Vector3Transition, IVector3TransitionFactory>([&](IVector3TransitionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline VisualState::VisualState() :
        VisualState(impl::call_factory_cast<VisualState(*)(winrt::Windows::Foundation::IActivationFactory const&), VisualState>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VisualState>(); }))
    {
    }
    inline VisualStateChangedEventArgs::VisualStateChangedEventArgs() :
        VisualStateChangedEventArgs(impl::call_factory_cast<VisualStateChangedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), VisualStateChangedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VisualStateChangedEventArgs>(); }))
    {
    }
    inline VisualStateGroup::VisualStateGroup() :
        VisualStateGroup(impl::call_factory_cast<VisualStateGroup(*)(winrt::Windows::Foundation::IActivationFactory const&), VisualStateGroup>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VisualStateGroup>(); }))
    {
    }
    inline VisualStateManager::VisualStateManager()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<VisualStateManager, IVisualStateManagerFactory>([&](IVisualStateManagerFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto VisualStateManager::GetVisualStateGroups(winrt::Windows::UI::Xaml::FrameworkElement const& obj)
    {
        return impl::call_factory<VisualStateManager, IVisualStateManagerStatics>([&](IVisualStateManagerStatics const& f) { return f.GetVisualStateGroups(obj); });
    }
    inline auto VisualStateManager::CustomVisualStateManagerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IVisualStateManagerStatics const&), VisualStateManager, IVisualStateManagerStatics>([](IVisualStateManagerStatics const& f) { return f.CustomVisualStateManagerProperty(); });
    }
    inline auto VisualStateManager::GetCustomVisualStateManager(winrt::Windows::UI::Xaml::FrameworkElement const& obj)
    {
        return impl::call_factory<VisualStateManager, IVisualStateManagerStatics>([&](IVisualStateManagerStatics const& f) { return f.GetCustomVisualStateManager(obj); });
    }
    inline auto VisualStateManager::SetCustomVisualStateManager(winrt::Windows::UI::Xaml::FrameworkElement const& obj, winrt::Windows::UI::Xaml::VisualStateManager const& value)
    {
        impl::call_factory<VisualStateManager, IVisualStateManagerStatics>([&](IVisualStateManagerStatics const& f) { return f.SetCustomVisualStateManager(obj, value); });
    }
    inline auto VisualStateManager::GoToState(winrt::Windows::UI::Xaml::Controls::Control const& control, param::hstring const& stateName, bool useTransitions)
    {
        return impl::call_factory<VisualStateManager, IVisualStateManagerStatics>([&](IVisualStateManagerStatics const& f) { return f.GoToState(control, stateName, useTransitions); });
    }
    inline VisualTransition::VisualTransition()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<VisualTransition, IVisualTransitionFactory>([&](IVisualTransitionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto Window::Current()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Window(*)(IWindowStatics const&), Window, IWindowStatics>([](IWindowStatics const& f) { return f.Current(); });
    }
    template <typename L> ApplicationInitializationCallback::ApplicationInitializationCallback(L handler) :
        ApplicationInitializationCallback(impl::make_delegate<ApplicationInitializationCallback>(std::forward<L>(handler)))
    {
    }
    template <typename F> ApplicationInitializationCallback::ApplicationInitializationCallback(F* handler) :
        ApplicationInitializationCallback([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ApplicationInitializationCallback::ApplicationInitializationCallback(O* object, M method) :
        ApplicationInitializationCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ApplicationInitializationCallback::ApplicationInitializationCallback(com_ptr<O>&& object, M method) :
        ApplicationInitializationCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ApplicationInitializationCallback::ApplicationInitializationCallback(weak_ref<O>&& object, M method) :
        ApplicationInitializationCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ApplicationInitializationCallback::operator()(winrt::Windows::UI::Xaml::ApplicationInitializationCallbackParams const& p) const
    {
        check_hresult((*(impl::abi_t<ApplicationInitializationCallback>**)this)->Invoke(*(void**)(&p)));
    }
    template <typename L> BindingFailedEventHandler::BindingFailedEventHandler(L handler) :
        BindingFailedEventHandler(impl::make_delegate<BindingFailedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> BindingFailedEventHandler::BindingFailedEventHandler(F* handler) :
        BindingFailedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> BindingFailedEventHandler::BindingFailedEventHandler(O* object, M method) :
        BindingFailedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> BindingFailedEventHandler::BindingFailedEventHandler(com_ptr<O>&& object, M method) :
        BindingFailedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> BindingFailedEventHandler::BindingFailedEventHandler(weak_ref<O>&& object, M method) :
        BindingFailedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto BindingFailedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::BindingFailedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<BindingFailedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> CreateDefaultValueCallback::CreateDefaultValueCallback(L handler) :
        CreateDefaultValueCallback(impl::make_delegate<CreateDefaultValueCallback>(std::forward<L>(handler)))
    {
    }
    template <typename F> CreateDefaultValueCallback::CreateDefaultValueCallback(F* handler) :
        CreateDefaultValueCallback([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> CreateDefaultValueCallback::CreateDefaultValueCallback(O* object, M method) :
        CreateDefaultValueCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> CreateDefaultValueCallback::CreateDefaultValueCallback(com_ptr<O>&& object, M method) :
        CreateDefaultValueCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> CreateDefaultValueCallback::CreateDefaultValueCallback(weak_ref<O>&& object, M method) :
        CreateDefaultValueCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto CreateDefaultValueCallback::operator()() const
    {
        void* result{};
        check_hresult((*(impl::abi_t<CreateDefaultValueCallback>**)this)->Invoke(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename L> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(L handler) :
        DependencyPropertyChangedCallback(impl::make_delegate<DependencyPropertyChangedCallback>(std::forward<L>(handler)))
    {
    }
    template <typename F> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(F* handler) :
        DependencyPropertyChangedCallback([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(O* object, M method) :
        DependencyPropertyChangedCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(com_ptr<O>&& object, M method) :
        DependencyPropertyChangedCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(weak_ref<O>&& object, M method) :
        DependencyPropertyChangedCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DependencyPropertyChangedCallback::operator()(winrt::Windows::UI::Xaml::DependencyObject const& sender, winrt::Windows::UI::Xaml::DependencyProperty const& dp) const
    {
        check_hresult((*(impl::abi_t<DependencyPropertyChangedCallback>**)this)->Invoke(*(void**)(&sender), *(void**)(&dp)));
    }
    template <typename L> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(L handler) :
        DependencyPropertyChangedEventHandler(impl::make_delegate<DependencyPropertyChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(F* handler) :
        DependencyPropertyChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(O* object, M method) :
        DependencyPropertyChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(com_ptr<O>&& object, M method) :
        DependencyPropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(weak_ref<O>&& object, M method) :
        DependencyPropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DependencyPropertyChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DependencyPropertyChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> DragEventHandler::DragEventHandler(L handler) :
        DragEventHandler(impl::make_delegate<DragEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DragEventHandler::DragEventHandler(F* handler) :
        DragEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DragEventHandler::DragEventHandler(O* object, M method) :
        DragEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragEventHandler::DragEventHandler(com_ptr<O>&& object, M method) :
        DragEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragEventHandler::DragEventHandler(weak_ref<O>&& object, M method) :
        DragEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DragEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::DragEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DragEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(L handler) :
        EnteredBackgroundEventHandler(impl::make_delegate<EnteredBackgroundEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(F* handler) :
        EnteredBackgroundEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(O* object, M method) :
        EnteredBackgroundEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(com_ptr<O>&& object, M method) :
        EnteredBackgroundEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(weak_ref<O>&& object, M method) :
        EnteredBackgroundEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto EnteredBackgroundEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<EnteredBackgroundEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(L handler) :
        ExceptionRoutedEventHandler(impl::make_delegate<ExceptionRoutedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(F* handler) :
        ExceptionRoutedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(O* object, M method) :
        ExceptionRoutedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(com_ptr<O>&& object, M method) :
        ExceptionRoutedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(weak_ref<O>&& object, M method) :
        ExceptionRoutedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ExceptionRoutedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::ExceptionRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ExceptionRoutedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(L handler) :
        LeavingBackgroundEventHandler(impl::make_delegate<LeavingBackgroundEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(F* handler) :
        LeavingBackgroundEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(O* object, M method) :
        LeavingBackgroundEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(com_ptr<O>&& object, M method) :
        LeavingBackgroundEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(weak_ref<O>&& object, M method) :
        LeavingBackgroundEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto LeavingBackgroundEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<LeavingBackgroundEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> PropertyChangedCallback::PropertyChangedCallback(L handler) :
        PropertyChangedCallback(impl::make_delegate<PropertyChangedCallback>(std::forward<L>(handler)))
    {
    }
    template <typename F> PropertyChangedCallback::PropertyChangedCallback(F* handler) :
        PropertyChangedCallback([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> PropertyChangedCallback::PropertyChangedCallback(O* object, M method) :
        PropertyChangedCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> PropertyChangedCallback::PropertyChangedCallback(com_ptr<O>&& object, M method) :
        PropertyChangedCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> PropertyChangedCallback::PropertyChangedCallback(weak_ref<O>&& object, M method) :
        PropertyChangedCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto PropertyChangedCallback::operator()(winrt::Windows::UI::Xaml::DependencyObject const& d, winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<PropertyChangedCallback>**)this)->Invoke(*(void**)(&d), *(void**)(&e)));
    }
    template <typename L> RoutedEventHandler::RoutedEventHandler(L handler) :
        RoutedEventHandler(impl::make_delegate<RoutedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> RoutedEventHandler::RoutedEventHandler(F* handler) :
        RoutedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> RoutedEventHandler::RoutedEventHandler(O* object, M method) :
        RoutedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> RoutedEventHandler::RoutedEventHandler(com_ptr<O>&& object, M method) :
        RoutedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> RoutedEventHandler::RoutedEventHandler(weak_ref<O>&& object, M method) :
        RoutedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto RoutedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<RoutedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> SizeChangedEventHandler::SizeChangedEventHandler(L handler) :
        SizeChangedEventHandler(impl::make_delegate<SizeChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> SizeChangedEventHandler::SizeChangedEventHandler(F* handler) :
        SizeChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(O* object, M method) :
        SizeChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(com_ptr<O>&& object, M method) :
        SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(weak_ref<O>&& object, M method) :
        SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto SizeChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::SizeChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<SizeChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> SuspendingEventHandler::SuspendingEventHandler(L handler) :
        SuspendingEventHandler(impl::make_delegate<SuspendingEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> SuspendingEventHandler::SuspendingEventHandler(F* handler) :
        SuspendingEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> SuspendingEventHandler::SuspendingEventHandler(O* object, M method) :
        SuspendingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> SuspendingEventHandler::SuspendingEventHandler(com_ptr<O>&& object, M method) :
        SuspendingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> SuspendingEventHandler::SuspendingEventHandler(weak_ref<O>&& object, M method) :
        SuspendingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto SuspendingEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::SuspendingEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<SuspendingEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(L handler) :
        UnhandledExceptionEventHandler(impl::make_delegate<UnhandledExceptionEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(F* handler) :
        UnhandledExceptionEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(O* object, M method) :
        UnhandledExceptionEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(com_ptr<O>&& object, M method) :
        UnhandledExceptionEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(weak_ref<O>&& object, M method) :
        UnhandledExceptionEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto UnhandledExceptionEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::UnhandledExceptionEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<UnhandledExceptionEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> VisualStateChangedEventHandler::VisualStateChangedEventHandler(L handler) :
        VisualStateChangedEventHandler(impl::make_delegate<VisualStateChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> VisualStateChangedEventHandler::VisualStateChangedEventHandler(F* handler) :
        VisualStateChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> VisualStateChangedEventHandler::VisualStateChangedEventHandler(O* object, M method) :
        VisualStateChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> VisualStateChangedEventHandler::VisualStateChangedEventHandler(com_ptr<O>&& object, M method) :
        VisualStateChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> VisualStateChangedEventHandler::VisualStateChangedEventHandler(weak_ref<O>&& object, M method) :
        VisualStateChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto VisualStateChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::VisualStateChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<VisualStateChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> WindowActivatedEventHandler::WindowActivatedEventHandler(L handler) :
        WindowActivatedEventHandler(impl::make_delegate<WindowActivatedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> WindowActivatedEventHandler::WindowActivatedEventHandler(F* handler) :
        WindowActivatedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> WindowActivatedEventHandler::WindowActivatedEventHandler(O* object, M method) :
        WindowActivatedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowActivatedEventHandler::WindowActivatedEventHandler(com_ptr<O>&& object, M method) :
        WindowActivatedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowActivatedEventHandler::WindowActivatedEventHandler(weak_ref<O>&& object, M method) :
        WindowActivatedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto WindowActivatedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Core::WindowActivatedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<WindowActivatedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> WindowClosedEventHandler::WindowClosedEventHandler(L handler) :
        WindowClosedEventHandler(impl::make_delegate<WindowClosedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> WindowClosedEventHandler::WindowClosedEventHandler(F* handler) :
        WindowClosedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> WindowClosedEventHandler::WindowClosedEventHandler(O* object, M method) :
        WindowClosedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowClosedEventHandler::WindowClosedEventHandler(com_ptr<O>&& object, M method) :
        WindowClosedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowClosedEventHandler::WindowClosedEventHandler(weak_ref<O>&& object, M method) :
        WindowClosedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto WindowClosedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Core::CoreWindowEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<WindowClosedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(L handler) :
        WindowSizeChangedEventHandler(impl::make_delegate<WindowSizeChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(F* handler) :
        WindowSizeChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(O* object, M method) :
        WindowSizeChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(com_ptr<O>&& object, M method) :
        WindowSizeChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(weak_ref<O>&& object, M method) :
        WindowSizeChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto WindowSizeChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Core::WindowSizeChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<WindowSizeChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(L handler) :
        WindowVisibilityChangedEventHandler(impl::make_delegate<WindowVisibilityChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(F* handler) :
        WindowVisibilityChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(O* object, M method) :
        WindowVisibilityChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(com_ptr<O>&& object, M method) :
        WindowVisibilityChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(weak_ref<O>&& object, M method) :
        WindowVisibilityChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto WindowVisibilityChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Core::VisibilityChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<WindowVisibilityChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnActivated(winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnLaunched(winrt::Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnLaunched(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnFileActivated(winrt::Windows::ApplicationModel::Activation::FileActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnFileActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnSearchActivated(winrt::Windows::ApplicationModel::Activation::SearchActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnSearchActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnShareTargetActivated(winrt::Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnShareTargetActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnFileOpenPickerActivated(winrt::Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnFileOpenPickerActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnFileSavePickerActivated(winrt::Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnFileSavePickerActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnCachedFileUpdaterActivated(winrt::Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnCachedFileUpdaterActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverridesT<D>::OnWindowCreated(winrt::Windows::UI::Xaml::WindowCreatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides>().OnWindowCreated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IApplicationOverrides2T<D>::OnBackgroundActivated(winrt::Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const& args) const
    {
        return shim().template try_as<IApplicationOverrides2>().OnBackgroundActivated(args);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) IFrameworkElementOverridesT<D>::MeasureOverride(winrt::Windows::Foundation::Size const& availableSize) const
    {
        return shim().template try_as<IFrameworkElementOverrides>().MeasureOverride(availableSize);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) IFrameworkElementOverridesT<D>::ArrangeOverride(winrt::Windows::Foundation::Size const& finalSize) const
    {
        return shim().template try_as<IFrameworkElementOverrides>().ArrangeOverride(finalSize);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IFrameworkElementOverridesT<D>::OnApplyTemplate() const
    {
        return shim().template try_as<IFrameworkElementOverrides>().OnApplyTemplate();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IFrameworkElementOverrides2T<D>::GoToElementStateCore(param::hstring const& stateName, bool useTransitions) const
    {
        return shim().template try_as<IFrameworkElementOverrides2>().GoToElementStateCore(stateName, useTransitions);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) IUIElementOverridesT<D>::OnCreateAutomationPeer() const
    {
        return shim().template try_as<IUIElementOverrides>().OnCreateAutomationPeer();
    }
    template <typename D> WINRT_IMPL_AUTO(void) IUIElementOverridesT<D>::OnDisconnectVisualChildren() const
    {
        return shim().template try_as<IUIElementOverrides>().OnDisconnectVisualChildren();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Point>>) IUIElementOverridesT<D>::FindSubElementsForTouchTargeting(winrt::Windows::Foundation::Point const& point, winrt::Windows::Foundation::Rect const& boundingRect) const
    {
        return shim().template try_as<IUIElementOverrides>().FindSubElementsForTouchTargeting(point, boundingRect);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::DependencyObject>) IUIElementOverrides7T<D>::GetChildrenInTabFocusOrder() const
    {
        return shim().template try_as<IUIElementOverrides7>().GetChildrenInTabFocusOrder();
    }
    template <typename D> WINRT_IMPL_AUTO(void) IUIElementOverrides7T<D>::OnProcessKeyboardAccelerators(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
    {
        return shim().template try_as<IUIElementOverrides7>().OnProcessKeyboardAccelerators(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IUIElementOverrides8T<D>::OnKeyboardAcceleratorInvoked(winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const& args) const
    {
        return shim().template try_as<IUIElementOverrides8>().OnKeyboardAcceleratorInvoked(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IUIElementOverrides8T<D>::OnBringIntoViewRequested(winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs const& e) const
    {
        return shim().template try_as<IUIElementOverrides8>().OnBringIntoViewRequested(e);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IUIElementOverrides9T<D>::PopulatePropertyInfoOverride(param::hstring const& propertyName, winrt::Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo) const
    {
        return shim().template try_as<IUIElementOverrides9>().PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IVisualStateManagerOverridesT<D>::GoToStateCore(winrt::Windows::UI::Xaml::Controls::Control const& control, winrt::Windows::UI::Xaml::FrameworkElement const& templateRoot, param::hstring const& stateName, winrt::Windows::UI::Xaml::VisualStateGroup const& group, winrt::Windows::UI::Xaml::VisualState const& state, bool useTransitions) const
    {
        return shim().template try_as<IVisualStateManagerOverrides>().GoToStateCore(control, templateRoot, stateName, group, state, useTransitions);
    }
    template <typename D, typename... Interfaces>
    struct AdaptiveTriggerT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IAdaptiveTrigger, winrt::Windows::UI::Xaml::IStateTriggerBase, winrt::Windows::UI::Xaml::IStateTriggerBaseProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, AdaptiveTrigger, winrt::Windows::UI::Xaml::StateTriggerBase, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = AdaptiveTrigger;
    protected:
        AdaptiveTriggerT()
        {
            impl::call_factory<AdaptiveTrigger, IAdaptiveTriggerFactory>([&](IAdaptiveTriggerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ApplicationT :
        implements<D, winrt::Windows::UI::Xaml::IApplicationOverrides, winrt::Windows::UI::Xaml::IApplicationOverrides2, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IApplication, winrt::Windows::UI::Xaml::IApplication2, winrt::Windows::UI::Xaml::IApplication3>,
        impl::base<D, Application>,
        winrt::Windows::UI::Xaml::IApplicationOverridesT<D>, winrt::Windows::UI::Xaml::IApplicationOverrides2T<D>
    {
        using composable = Application;
    protected:
        ApplicationT()
        {
            impl::call_factory<Application, IApplicationFactory>([&](IApplicationFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct BrushTransitionT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IBrushTransition>,
        impl::base<D, BrushTransition>
    {
        using composable = BrushTransition;
    protected:
        BrushTransitionT()
        {
            impl::call_factory<BrushTransition, IBrushTransitionFactory>([&](IBrushTransitionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ColorPaletteResourcesT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IColorPaletteResources, winrt::Windows::UI::Xaml::IResourceDictionary, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>>, winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ColorPaletteResources, winrt::Windows::UI::Xaml::ResourceDictionary, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = ColorPaletteResources;
    protected:
        ColorPaletteResourcesT()
        {
            impl::call_factory<ColorPaletteResources, IColorPaletteResourcesFactory>([&](IColorPaletteResourcesFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DataTemplateT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IDataTemplate, winrt::Windows::UI::Xaml::IElementFactory, winrt::Windows::UI::Xaml::IFrameworkTemplate, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, DataTemplate, winrt::Windows::UI::Xaml::FrameworkTemplate, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = DataTemplate;
    protected:
        DataTemplateT()
        {
            impl::call_factory<DataTemplate, IDataTemplateFactory>([&](IDataTemplateFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DataTemplateKeyT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IDataTemplateKey>,
        impl::base<D, DataTemplateKey>
    {
        using composable = DataTemplateKey;
    protected:
        DataTemplateKeyT()
        {
            impl::call_factory<DataTemplateKey, IDataTemplateKeyFactory>([&](IDataTemplateKeyFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
        DataTemplateKeyT(winrt::Windows::Foundation::IInspectable const& dataType)
        {
            impl::call_factory<DataTemplateKey, IDataTemplateKeyFactory>([&](IDataTemplateKeyFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithType(dataType, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DependencyObjectT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, DependencyObject>
    {
        using composable = DependencyObject;
    protected:
        DependencyObjectT()
        {
            impl::call_factory<DependencyObject, IDependencyObjectFactory>([&](IDependencyObjectFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DependencyObjectCollectionT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::DependencyObject>, winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::DependencyObject>, winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::Xaml::DependencyObject>, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, DependencyObjectCollection, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = DependencyObjectCollection;
    protected:
        DependencyObjectCollectionT()
        {
            impl::call_factory<DependencyObjectCollection, IDependencyObjectCollectionFactory>([&](IDependencyObjectCollectionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DispatcherTimerT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IDispatcherTimer>,
        impl::base<D, DispatcherTimer>
    {
        using composable = DispatcherTimer;
    protected:
        DispatcherTimerT()
        {
            impl::call_factory<DispatcherTimer, IDispatcherTimerFactory>([&](IDispatcherTimerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ElementFactoryGetArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IElementFactoryGetArgs>,
        impl::base<D, ElementFactoryGetArgs>
    {
        using composable = ElementFactoryGetArgs;
    protected:
        ElementFactoryGetArgsT()
        {
            impl::call_factory<ElementFactoryGetArgs, IElementFactoryGetArgsFactory>([&](IElementFactoryGetArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ElementFactoryRecycleArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs>,
        impl::base<D, ElementFactoryRecycleArgs>
    {
        using composable = ElementFactoryRecycleArgs;
    protected:
        ElementFactoryRecycleArgsT()
        {
            impl::call_factory<ElementFactoryRecycleArgs, IElementFactoryRecycleArgsFactory>([&](IElementFactoryRecycleArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FrameworkElementT :
        implements<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = FrameworkElement;
    protected:
        FrameworkElementT()
        {
            impl::call_factory<FrameworkElement, IFrameworkElementFactory>([&](IFrameworkElementFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FrameworkTemplateT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IFrameworkTemplate, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FrameworkTemplate, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = FrameworkTemplate;
    protected:
        FrameworkTemplateT()
        {
            impl::call_factory<FrameworkTemplate, IFrameworkTemplateFactory>([&](IFrameworkTemplateFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct PropertyMetadataT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IPropertyMetadata>,
        impl::base<D, PropertyMetadata>
    {
        using composable = PropertyMetadata;
    protected:
        PropertyMetadataT(winrt::Windows::Foundation::IInspectable const& defaultValue)
        {
            impl::call_factory<PropertyMetadata, IPropertyMetadataFactory>([&](IPropertyMetadataFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithDefaultValue(defaultValue, *this, this->m_inner); });
        }
        PropertyMetadataT(winrt::Windows::Foundation::IInspectable const& defaultValue, winrt::Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
        {
            impl::call_factory<PropertyMetadata, IPropertyMetadataFactory>([&](IPropertyMetadataFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithDefaultValueAndCallback(defaultValue, propertyChangedCallback, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ResourceDictionaryT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IResourceDictionary, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>>, winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable>, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ResourceDictionary, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = ResourceDictionary;
    protected:
        ResourceDictionaryT()
        {
            impl::call_factory<ResourceDictionary, IResourceDictionaryFactory>([&](IResourceDictionaryFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RoutedEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IRoutedEventArgs>,
        impl::base<D, RoutedEventArgs>
    {
        using composable = RoutedEventArgs;
    protected:
        RoutedEventArgsT()
        {
            impl::call_factory<RoutedEventArgs, IRoutedEventArgsFactory>([&](IRoutedEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ScalarTransitionT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IScalarTransition>,
        impl::base<D, ScalarTransition>
    {
        using composable = ScalarTransition;
    protected:
        ScalarTransitionT()
        {
            impl::call_factory<ScalarTransition, IScalarTransitionFactory>([&](IScalarTransitionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct StateTriggerBaseT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IStateTriggerBase, winrt::Windows::UI::Xaml::IStateTriggerBaseProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, StateTriggerBase, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = StateTriggerBase;
    protected:
        StateTriggerBaseT()
        {
            impl::call_factory<StateTriggerBase, IStateTriggerBaseFactory>([&](IStateTriggerBaseFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct UIElementWeakCollectionT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IUIElementWeakCollection, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::UIElement>, winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::UIElement>>,
        impl::base<D, UIElementWeakCollection>
    {
        using composable = UIElementWeakCollection;
    protected:
        UIElementWeakCollectionT()
        {
            impl::call_factory<UIElementWeakCollection, IUIElementWeakCollectionFactory>([&](IUIElementWeakCollectionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct Vector3TransitionT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IVector3Transition>,
        impl::base<D, Vector3Transition>
    {
        using composable = Vector3Transition;
    protected:
        Vector3TransitionT()
        {
            impl::call_factory<Vector3Transition, IVector3TransitionFactory>([&](IVector3TransitionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct VisualStateManagerT :
        implements<D, winrt::Windows::UI::Xaml::IVisualStateManagerOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IVisualStateManager, winrt::Windows::UI::Xaml::IVisualStateManagerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, VisualStateManager, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::IVisualStateManagerOverridesT<D>
    {
        using composable = VisualStateManager;
    protected:
        VisualStateManagerT()
        {
            impl::call_factory<VisualStateManager, IVisualStateManagerFactory>([&](IVisualStateManagerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct VisualTransitionT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::IVisualTransition, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, VisualTransition, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = VisualTransition;
    protected:
        VisualTransitionT()
        {
            impl::call_factory<VisualTransition, IVisualTransitionFactory>([&](IVisualTransitionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::IAdaptiveTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IAdaptiveTriggerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplication> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplication2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplication3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplicationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplicationInitializationCallbackParams> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplicationOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplicationOverrides2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IApplicationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IBindingFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IBringIntoViewOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IBringIntoViewOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IBrushTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IBrushTransitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IColorPaletteResources> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IColorPaletteResourcesFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ICornerRadiusHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataContextChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateKey> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateKeyFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObject2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObjectCollectionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObjectFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDependencyPropertyStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDispatcherTimer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDispatcherTimerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragEventArgs3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragOperationDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragStartingEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDragUIOverride> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDropCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDurationHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IDurationHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryGetArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryGetArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryRecycleArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementSoundPlayer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementSoundPlayerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IEventTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IExceptionRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IExceptionRoutedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementOverrides2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementProtected7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkTemplate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkTemplateFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkViewSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IGridLengthHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IGridLengthHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IMediaFailedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPointHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPointHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPropertyMetadata> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPropertyMetadataFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPropertyMetadataStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPropertyPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IPropertyPathFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IRectHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IRectHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IResourceDictionary> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IResourceDictionaryFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IRoutedEvent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IRoutedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IScalarTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IScalarTransitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISetter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISetter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISetterBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISetterBaseCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISetterBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISetterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISizeChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISizeHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ISizeHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStateTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerBaseProtected> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStyle> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IStyleFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ITargetPropertyPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ITargetPropertyPathFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IThicknessHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IThicknessHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ITriggerAction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ITriggerActionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ITriggerBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ITriggerBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement10> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement8> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElement9> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides8> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides9> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics10> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics8> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics9> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementWeakCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUIElementWeakCollectionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVector3Transition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVector3TransitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualState2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerProtected> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IVisualTransitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IWindow2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IWindow3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IWindow4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IWindowCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IWindowStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IXamlRoot> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::IXamlRootChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::AdaptiveTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Application> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ApplicationInitializationCallbackParams> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::BindingFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::BringIntoViewOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::BrushTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ColorPaletteResources> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::CornerRadiusHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DataContextChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DataTemplate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DataTemplateKey> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DebugSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DependencyObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DependencyObjectCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DependencyProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DispatcherTimer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DragEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DragOperationDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DragStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DragUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DragUIOverride> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DropCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::DurationHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::EffectiveViewportChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ElementFactoryGetArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ElementSoundPlayer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::EventTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ExceptionRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::FrameworkElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::FrameworkTemplate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::FrameworkView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::FrameworkViewSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::GridLengthHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::MediaFailedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::PointHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::PropertyMetadata> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::PropertyPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::RectHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ResourceDictionary> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::RoutedEvent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::RoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ScalarTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Setter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::SetterBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::SetterBaseCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::SizeChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::SizeHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::StateTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::StateTriggerBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Style> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::TargetPropertyPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::ThicknessHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::TriggerAction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::TriggerActionCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::TriggerBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::TriggerCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::UIElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::UIElementWeakCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::UnhandledExceptionEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Vector3Transition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::VisualState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::VisualStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::VisualStateGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::VisualStateManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::VisualTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Window> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::WindowCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::XamlRoot> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::XamlRootChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
