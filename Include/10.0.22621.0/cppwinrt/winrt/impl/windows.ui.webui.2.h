// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WebUI_2_H
#define WINRT_Windows_UI_WebUI_2_H
#include "winrt/impl/Windows.ApplicationModel.1.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.1.h"
#include "winrt/impl/Windows.ApplicationModel.Background.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.Printing.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Web.UI.1.h"
#include "winrt/impl/Windows.UI.WebUI.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::WebUI
{
    struct ActivatedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        ActivatedEventHandler(std::nullptr_t = nullptr) noexcept {}
        ActivatedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> ActivatedEventHandler(L lambda);
        template <typename F> ActivatedEventHandler(F* function);
        template <typename O, typename M> ActivatedEventHandler(O* object, M method);
        template <typename O, typename M> ActivatedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> ActivatedEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const& eventArgs) const;
    };
    struct BackgroundActivatedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        BackgroundActivatedEventHandler(std::nullptr_t = nullptr) noexcept {}
        BackgroundActivatedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> BackgroundActivatedEventHandler(L lambda);
        template <typename F> BackgroundActivatedEventHandler(F* function);
        template <typename O, typename M> BackgroundActivatedEventHandler(O* object, M method);
        template <typename O, typename M> BackgroundActivatedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> BackgroundActivatedEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs const& eventArgs) const;
    };
    struct EnteredBackgroundEventHandler : winrt::Windows::Foundation::IUnknown
    {
        EnteredBackgroundEventHandler(std::nullptr_t = nullptr) noexcept {}
        EnteredBackgroundEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> EnteredBackgroundEventHandler(L lambda);
        template <typename F> EnteredBackgroundEventHandler(F* function);
        template <typename O, typename M> EnteredBackgroundEventHandler(O* object, M method);
        template <typename O, typename M> EnteredBackgroundEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> EnteredBackgroundEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::IEnteredBackgroundEventArgs const& e) const;
    };
    struct LeavingBackgroundEventHandler : winrt::Windows::Foundation::IUnknown
    {
        LeavingBackgroundEventHandler(std::nullptr_t = nullptr) noexcept {}
        LeavingBackgroundEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> LeavingBackgroundEventHandler(L lambda);
        template <typename F> LeavingBackgroundEventHandler(F* function);
        template <typename O, typename M> LeavingBackgroundEventHandler(O* object, M method);
        template <typename O, typename M> LeavingBackgroundEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> LeavingBackgroundEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::ILeavingBackgroundEventArgs const& e) const;
    };
    struct NavigatedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        NavigatedEventHandler(std::nullptr_t = nullptr) noexcept {}
        NavigatedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> NavigatedEventHandler(L lambda);
        template <typename F> NavigatedEventHandler(F* function);
        template <typename O, typename M> NavigatedEventHandler(O* object, M method);
        template <typename O, typename M> NavigatedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> NavigatedEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::WebUI::IWebUINavigatedEventArgs const& e) const;
    };
    struct ResumingEventHandler : winrt::Windows::Foundation::IUnknown
    {
        ResumingEventHandler(std::nullptr_t = nullptr) noexcept {}
        ResumingEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> ResumingEventHandler(L lambda);
        template <typename F> ResumingEventHandler(F* function);
        template <typename O, typename M> ResumingEventHandler(O* object, M method);
        template <typename O, typename M> ResumingEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> ResumingEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender) const;
    };
    struct SuspendingEventHandler : winrt::Windows::Foundation::IUnknown
    {
        SuspendingEventHandler(std::nullptr_t = nullptr) noexcept {}
        SuspendingEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> SuspendingEventHandler(L lambda);
        template <typename F> SuspendingEventHandler(F* function);
        template <typename O, typename M> SuspendingEventHandler(O* object, M method);
        template <typename O, typename M> SuspendingEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> SuspendingEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::ApplicationModel::ISuspendingEventArgs const& e) const;
    };
    struct __declspec(empty_bases) ActivatedDeferral : winrt::Windows::UI::WebUI::IActivatedDeferral
    {
        ActivatedDeferral(std::nullptr_t) noexcept {}
        ActivatedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IActivatedDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ActivatedOperation : winrt::Windows::UI::WebUI::IActivatedOperation
    {
        ActivatedOperation(std::nullptr_t) noexcept {}
        ActivatedOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IActivatedOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BackgroundActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs
    {
        BackgroundActivatedEventArgs(std::nullptr_t) noexcept {}
        BackgroundActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) EnteredBackgroundEventArgs : winrt::Windows::ApplicationModel::IEnteredBackgroundEventArgs
    {
        EnteredBackgroundEventArgs(std::nullptr_t) noexcept {}
        EnteredBackgroundEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::IEnteredBackgroundEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HtmlPrintDocumentSource : winrt::Windows::UI::WebUI::IHtmlPrintDocumentSource,
        impl::require<HtmlPrintDocumentSource, winrt::Windows::Foundation::IClosable>
    {
        HtmlPrintDocumentSource(std::nullptr_t) noexcept {}
        HtmlPrintDocumentSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IHtmlPrintDocumentSource(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LeavingBackgroundEventArgs : winrt::Windows::ApplicationModel::ILeavingBackgroundEventArgs
    {
        LeavingBackgroundEventArgs(std::nullptr_t) noexcept {}
        LeavingBackgroundEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ILeavingBackgroundEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) NewWebUIViewCreatedEventArgs : winrt::Windows::UI::WebUI::INewWebUIViewCreatedEventArgs
    {
        NewWebUIViewCreatedEventArgs(std::nullptr_t) noexcept {}
        NewWebUIViewCreatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::INewWebUIViewCreatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SuspendingDeferral : winrt::Windows::ApplicationModel::ISuspendingDeferral
    {
        SuspendingDeferral(std::nullptr_t) noexcept {}
        SuspendingDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ISuspendingDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SuspendingEventArgs : winrt::Windows::ApplicationModel::ISuspendingEventArgs
    {
        SuspendingEventArgs(std::nullptr_t) noexcept {}
        SuspendingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ISuspendingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SuspendingOperation : winrt::Windows::ApplicationModel::ISuspendingOperation
    {
        SuspendingOperation(std::nullptr_t) noexcept {}
        SuspendingOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ISuspendingOperation(ptr, take_ownership_from_abi) {}
    };
    struct WebUIApplication
    {
        WebUIApplication() = delete;
        static auto Activated(winrt::Windows::UI::WebUI::ActivatedEventHandler const& handler);
        using Activated_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics>::remove_Activated>;
        [[nodiscard]] static Activated_revoker Activated(auto_revoke_t, winrt::Windows::UI::WebUI::ActivatedEventHandler const& handler);
        static auto Activated(winrt::event_token const& token);
        static auto Suspending(winrt::Windows::UI::WebUI::SuspendingEventHandler const& handler);
        using Suspending_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics>::remove_Suspending>;
        [[nodiscard]] static Suspending_revoker Suspending(auto_revoke_t, winrt::Windows::UI::WebUI::SuspendingEventHandler const& handler);
        static auto Suspending(winrt::event_token const& token);
        static auto Resuming(winrt::Windows::UI::WebUI::ResumingEventHandler const& handler);
        using Resuming_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics>::remove_Resuming>;
        [[nodiscard]] static Resuming_revoker Resuming(auto_revoke_t, winrt::Windows::UI::WebUI::ResumingEventHandler const& handler);
        static auto Resuming(winrt::event_token const& token);
        static auto Navigated(winrt::Windows::UI::WebUI::NavigatedEventHandler const& handler);
        using Navigated_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics>::remove_Navigated>;
        [[nodiscard]] static Navigated_revoker Navigated(auto_revoke_t, winrt::Windows::UI::WebUI::NavigatedEventHandler const& handler);
        static auto Navigated(winrt::event_token const& token);
        static auto LeavingBackground(winrt::Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler);
        using LeavingBackground_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics2, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics2>::remove_LeavingBackground>;
        [[nodiscard]] static LeavingBackground_revoker LeavingBackground(auto_revoke_t, winrt::Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler);
        static auto LeavingBackground(winrt::event_token const& token);
        static auto EnteredBackground(winrt::Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler);
        using EnteredBackground_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics2, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics2>::remove_EnteredBackground>;
        [[nodiscard]] static EnteredBackground_revoker EnteredBackground(auto_revoke_t, winrt::Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler);
        static auto EnteredBackground(winrt::event_token const& token);
        static auto EnablePrelaunch(bool value);
        static auto RequestRestartAsync(param::hstring const& launchArguments);
        static auto RequestRestartForUserAsync(winrt::Windows::System::User const& user, param::hstring const& launchArguments);
        static auto NewWebUIViewCreated(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler);
        using NewWebUIViewCreated_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics4, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics4>::remove_NewWebUIViewCreated>;
        [[nodiscard]] static NewWebUIViewCreated_revoker NewWebUIViewCreated(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler);
        static auto NewWebUIViewCreated(winrt::event_token const& token);
        static auto BackgroundActivated(winrt::Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler);
        using BackgroundActivated_revoker = impl::factory_event_revoker<winrt::Windows::UI::WebUI::IWebUIActivationStatics4, &impl::abi_t<winrt::Windows::UI::WebUI::IWebUIActivationStatics4>::remove_BackgroundActivated>;
        [[nodiscard]] static BackgroundActivated_revoker BackgroundActivated(auto_revoke_t, winrt::Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler);
        static auto BackgroundActivated(winrt::event_token const& token);
    };
    struct __declspec(empty_bases) WebUIAppointmentsProviderAddAppointmentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderAddAppointmentActivatedEventArgs,
        impl::require<WebUIAppointmentsProviderAddAppointmentActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIAppointmentsProviderAddAppointmentActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIAppointmentsProviderAddAppointmentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderAddAppointmentActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderRemoveAppointmentActivatedEventArgs,
        impl::require<WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderRemoveAppointmentActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderReplaceAppointmentActivatedEventArgs,
        impl::require<WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderReplaceAppointmentActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowAppointmentDetailsActivatedEventArgs,
        impl::require<WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowAppointmentDetailsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowTimeFrameActivatedEventArgs,
        impl::require<WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IAppointmentsProviderShowTimeFrameActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct WebUIBackgroundTaskInstance
    {
        WebUIBackgroundTaskInstance() = delete;
        [[nodiscard]] static auto Current();
    };
    struct __declspec(empty_bases) WebUIBackgroundTaskInstanceRuntimeClass : winrt::Windows::UI::WebUI::IWebUIBackgroundTaskInstance,
        impl::require<WebUIBackgroundTaskInstanceRuntimeClass, winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance>
    {
        WebUIBackgroundTaskInstanceRuntimeClass(std::nullptr_t) noexcept {}
        WebUIBackgroundTaskInstanceRuntimeClass(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IWebUIBackgroundTaskInstance(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIBarcodeScannerPreviewActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IBarcodeScannerPreviewActivatedEventArgs,
        impl::require<WebUIBarcodeScannerPreviewActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIBarcodeScannerPreviewActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIBarcodeScannerPreviewActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IBarcodeScannerPreviewActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUICachedFileUpdaterActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ICachedFileUpdaterActivatedEventArgs,
        impl::require<WebUICachedFileUpdaterActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUICachedFileUpdaterActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUICachedFileUpdaterActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICachedFileUpdaterActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUICameraSettingsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ICameraSettingsActivatedEventArgs,
        impl::require<WebUICameraSettingsActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUICameraSettingsActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUICameraSettingsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICameraSettingsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUICommandLineActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ICommandLineActivatedEventArgs,
        impl::require<WebUICommandLineActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUICommandLineActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUICommandLineActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ICommandLineActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactCallActivatedEventArgs,
        impl::require<WebUIContactCallActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIContactCallActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactMapActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactMapActivatedEventArgs,
        impl::require<WebUIContactMapActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIContactMapActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactMapActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactMapActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactMessageActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactMessageActivatedEventArgs,
        impl::require<WebUIContactMessageActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIContactMessageActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactMessageActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactMessageActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactPanelActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactPanelActivatedEventArgs,
        impl::require<WebUIContactPanelActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIContactPanelActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactPanelActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactPanelActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactPickerActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactPickerActivatedEventArgs,
        impl::require<WebUIContactPickerActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIContactPickerActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactPickerActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactPickerActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactPostActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactPostActivatedEventArgs,
        impl::require<WebUIContactPostActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIContactPostActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactPostActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactPostActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIContactVideoCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IContactVideoCallActivatedEventArgs,
        impl::require<WebUIContactVideoCallActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIContactVideoCallActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIContactVideoCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IContactVideoCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIDeviceActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IDeviceActivatedEventArgs,
        impl::require<WebUIDeviceActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIDeviceActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIDeviceActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IDeviceActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIDevicePairingActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IDevicePairingActivatedEventArgs,
        impl::require<WebUIDevicePairingActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIDevicePairingActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIDevicePairingActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IDevicePairingActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIDialReceiverActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IDialReceiverActivatedEventArgs,
        impl::require<WebUIDialReceiverActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIDialReceiverActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIDialReceiverActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IDialReceiverActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIFileActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgs,
        impl::require<WebUIFileActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgsWithNeighboringFiles, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIFileActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIFileActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIFileOpenPickerActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs,
        impl::require<WebUIFileOpenPickerActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs2, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIFileOpenPickerActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIFileOpenPickerActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIFileOpenPickerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerContinuationEventArgs,
        impl::require<WebUIFileOpenPickerContinuationEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIFileOpenPickerContinuationEventArgs(std::nullptr_t) noexcept {}
        WebUIFileOpenPickerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileOpenPickerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIFileSavePickerActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs,
        impl::require<WebUIFileSavePickerActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs2, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIFileSavePickerActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIFileSavePickerActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIFileSavePickerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IFileSavePickerContinuationEventArgs,
        impl::require<WebUIFileSavePickerContinuationEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIFileSavePickerContinuationEventArgs(std::nullptr_t) noexcept {}
        WebUIFileSavePickerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFileSavePickerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIFolderPickerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IFolderPickerContinuationEventArgs,
        impl::require<WebUIFolderPickerContinuationEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIFolderPickerContinuationEventArgs(std::nullptr_t) noexcept {}
        WebUIFolderPickerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IFolderPickerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUILaunchActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs,
        impl::require<WebUILaunchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IPrelaunchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser, winrt::Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs2>
    {
        WebUILaunchActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUILaunchActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUILockScreenActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ILockScreenActivatedEventArgs,
        impl::require<WebUILockScreenActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUILockScreenActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUILockScreenActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ILockScreenActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUILockScreenCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ILockScreenCallActivatedEventArgs,
        impl::require<WebUILockScreenCallActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUILockScreenCallActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUILockScreenCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ILockScreenCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUILockScreenComponentActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs,
        impl::require<WebUILockScreenComponentActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUILockScreenComponentActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUILockScreenComponentActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUINavigatedDeferral : winrt::Windows::UI::WebUI::IWebUINavigatedDeferral
    {
        WebUINavigatedDeferral(std::nullptr_t) noexcept {}
        WebUINavigatedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IWebUINavigatedDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUINavigatedEventArgs : winrt::Windows::UI::WebUI::IWebUINavigatedEventArgs
    {
        WebUINavigatedEventArgs(std::nullptr_t) noexcept {}
        WebUINavigatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IWebUINavigatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUINavigatedOperation : winrt::Windows::UI::WebUI::IWebUINavigatedOperation
    {
        WebUINavigatedOperation(std::nullptr_t) noexcept {}
        WebUINavigatedOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IWebUINavigatedOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIPhoneCallActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPhoneCallActivatedEventArgs,
        impl::require<WebUIPhoneCallActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIPhoneCallActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIPhoneCallActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPhoneCallActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIPrint3DWorkflowActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPrint3DWorkflowActivatedEventArgs,
        impl::require<WebUIPrint3DWorkflowActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIPrint3DWorkflowActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIPrint3DWorkflowActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPrint3DWorkflowActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIPrintTaskSettingsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IPrintTaskSettingsActivatedEventArgs,
        impl::require<WebUIPrintTaskSettingsActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIPrintTaskSettingsActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIPrintTaskSettingsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IPrintTaskSettingsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIPrintWorkflowForegroundTaskActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs,
        impl::require<WebUIPrintWorkflowForegroundTaskActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIPrintWorkflowForegroundTaskActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIPrintWorkflowForegroundTaskActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIProtocolActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs,
        impl::require<WebUIProtocolActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgsWithCallerPackageFamilyNameAndData, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIProtocolActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIProtocolActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIProtocolForResultsActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IProtocolForResultsActivatedEventArgs,
        impl::require<WebUIProtocolForResultsActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IProtocolActivatedEventArgsWithCallerPackageFamilyNameAndData, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIProtocolForResultsActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIProtocolForResultsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IProtocolForResultsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIRestrictedLaunchActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IRestrictedLaunchActivatedEventArgs,
        impl::require<WebUIRestrictedLaunchActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIRestrictedLaunchActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIRestrictedLaunchActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IRestrictedLaunchActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUISearchActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::ISearchActivatedEventArgs,
        impl::require<WebUISearchActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::ISearchActivatedEventArgsWithLinguisticDetails, winrt::Windows::ApplicationModel::Activation::IApplicationViewActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUISearchActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUISearchActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::ISearchActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIShareTargetActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IShareTargetActivatedEventArgs,
        impl::require<WebUIShareTargetActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIShareTargetActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIShareTargetActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IShareTargetActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIStartupTaskActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IStartupTaskActivatedEventArgs,
        impl::require<WebUIStartupTaskActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIStartupTaskActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIStartupTaskActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IStartupTaskActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIToastNotificationActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IToastNotificationActivatedEventArgs,
        impl::require<WebUIToastNotificationActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIToastNotificationActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIToastNotificationActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IToastNotificationActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIUserDataAccountProviderActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IUserDataAccountProviderActivatedEventArgs,
        impl::require<WebUIUserDataAccountProviderActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIUserDataAccountProviderActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIUserDataAccountProviderActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IUserDataAccountProviderActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIView : winrt::Windows::UI::WebUI::IWebUIView,
        impl::require<WebUIView, winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::IWebViewControl2>
    {
        WebUIView(std::nullptr_t) noexcept {}
        WebUIView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WebUI::IWebUIView(ptr, take_ownership_from_abi) {}
        static auto CreateAsync();
        static auto CreateAsync(winrt::Windows::Foundation::Uri const& uri);
    };
    struct __declspec(empty_bases) WebUIVoiceCommandActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IVoiceCommandActivatedEventArgs,
        impl::require<WebUIVoiceCommandActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIVoiceCommandActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIVoiceCommandActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IVoiceCommandActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIWalletActionActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IWalletActionActivatedEventArgs,
        impl::require<WebUIWalletActionActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIWalletActionActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIWalletActionActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IWalletActionActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIWebAccountProviderActivatedEventArgs : winrt::Windows::ApplicationModel::Activation::IWebAccountProviderActivatedEventArgs,
        impl::require<WebUIWebAccountProviderActivatedEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        WebUIWebAccountProviderActivatedEventArgs(std::nullptr_t) noexcept {}
        WebUIWebAccountProviderActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IWebAccountProviderActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebUIWebAuthenticationBrokerContinuationEventArgs : winrt::Windows::ApplicationModel::Activation::IWebAuthenticationBrokerContinuationEventArgs,
        impl::require<WebUIWebAuthenticationBrokerContinuationEventArgs, winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral>
    {
        WebUIWebAuthenticationBrokerContinuationEventArgs(std::nullptr_t) noexcept {}
        WebUIWebAuthenticationBrokerContinuationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Activation::IWebAuthenticationBrokerContinuationEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
