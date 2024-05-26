// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_H
#define WINRT_Windows_UI_Notifications_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::AdaptiveNotificationContentKind) consume_Windows_UI_Notifications_IAdaptiveNotificationContent<D>::Kind() const
    {
        winrt::Windows::UI::Notifications::AdaptiveNotificationContentKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IAdaptiveNotificationContent)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_UI_Notifications_IAdaptiveNotificationContent<D>::Hints() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IAdaptiveNotificationContent)->get_Hints(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IAdaptiveNotificationText)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IAdaptiveNotificationText)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IAdaptiveNotificationText)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IAdaptiveNotificationText)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_IBadgeNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeNotification)->get_Content(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IBadgeNotification<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeNotification)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_IBadgeNotification<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeNotification)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeNotification) consume_Windows_UI_Notifications_IBadgeNotificationFactory<D>::CreateBadgeNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeNotificationFactory)->CreateBadgeNotification(*(void**)(&content), &value));
        return winrt::Windows::UI::Notifications::BadgeNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdater) consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::CreateBadgeUpdaterForApplication() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser)->CreateBadgeUpdaterForApplication(&result));
        return winrt::Windows::UI::Notifications::BadgeUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdater) consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::CreateBadgeUpdaterForApplication(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser)->CreateBadgeUpdaterForApplicationWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::BadgeUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdater) consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser)->CreateBadgeUpdaterForSecondaryTile(*(void**)(&tileId), &result));
        return winrt::Windows::UI::Notifications::BadgeUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdater) consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::CreateBadgeUpdaterForApplication() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics)->CreateBadgeUpdaterForApplication(&result));
        return winrt::Windows::UI::Notifications::BadgeUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdater) consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::CreateBadgeUpdaterForApplication(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics)->CreateBadgeUpdaterForApplicationWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::BadgeUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdater) consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics)->CreateBadgeUpdaterForSecondaryTile(*(void**)(&tileId), &result));
        return winrt::Windows::UI::Notifications::BadgeUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::GetTemplateContent(winrt::Windows::UI::Notifications::BadgeTemplateType const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics)->GetTemplateContent(static_cast<int32_t>(type), &result));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeUpdateManagerForUser) consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics2<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics2)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::UI::Notifications::BadgeUpdateManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IBadgeUpdater<D>::Update(winrt::Windows::UI::Notifications::BadgeNotification const& notification) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdater)->Update(*(void**)(&notification)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IBadgeUpdater<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdater)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IBadgeUpdater<D>::StartPeriodicUpdate(winrt::Windows::Foundation::Uri const& badgeContent, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdater)->StartPeriodicUpdate(*(void**)(&badgeContent), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IBadgeUpdater<D>::StartPeriodicUpdate(winrt::Windows::Foundation::Uri const& badgeContent, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdater)->StartPeriodicUpdateAtTime(*(void**)(&badgeContent), impl::bind_in(startTime), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IBadgeUpdater<D>::StopPeriodicUpdate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IBadgeUpdater)->StopPeriodicUpdate());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::Style() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_Style(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::Wrap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_Wrap(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::MaxLines() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_MaxLines(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::MinLines() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_MinLines(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::TextStacking() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_TextStacking(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::Align() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_Align(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Caption() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Caption(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Body() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Body(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Base() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Base(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Subtitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Subtitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Subheader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Subheader(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Header() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Header(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::TitleNumeral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_TitleNumeral(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubheaderNumeral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubheaderNumeral(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::HeaderNumeral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_HeaderNumeral(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::CaptionSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_CaptionSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::BodySubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_BodySubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::BaseSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_BaseSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubtitleSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubtitleSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::TitleSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_TitleSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubheaderSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubheaderSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubheaderNumeralSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubheaderNumeralSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::HeaderSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_HeaderSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::HeaderNumeralSubtle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_HeaderNumeralSubtle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IKnownNotificationBindingsStatics<D>::ToastGeneric() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IKnownNotificationBindingsStatics)->get_ToastGeneric(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_INotification<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotification)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_INotification<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotification)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationVisual) consume_Windows_UI_Notifications_INotification<D>::Visual() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotification)->get_Visual(&value));
        return winrt::Windows::UI::Notifications::NotificationVisual{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_INotification<D>::Visual(winrt::Windows::UI::Notifications::NotificationVisual const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotification)->put_Visual(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_INotificationBinding<D>::Template() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationBinding)->get_Template(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_INotificationBinding<D>::Template(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationBinding)->put_Template(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_INotificationBinding<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationBinding)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_INotificationBinding<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationBinding)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_UI_Notifications_INotificationBinding<D>::Hints() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationBinding)->get_Hints(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::AdaptiveNotificationText>) consume_Windows_UI_Notifications_INotificationBinding<D>::GetTextElements() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationBinding)->GetTextElements(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::AdaptiveNotificationText>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_UI_Notifications_INotificationData<D>::Values() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationData)->get_Values(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Notifications_INotificationData<D>::SequenceNumber() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationData)->get_SequenceNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_INotificationData<D>::SequenceNumber(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationData)->put_SequenceNumber(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationData) consume_Windows_UI_Notifications_INotificationDataFactory<D>::CreateNotificationData(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues, uint32_t sequenceNumber) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationDataFactory)->CreateNotificationDataWithValuesAndSequenceNumber(*(void**)(&initialValues), sequenceNumber, &value));
        return winrt::Windows::UI::Notifications::NotificationData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationData) consume_Windows_UI_Notifications_INotificationDataFactory<D>::CreateNotificationData(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationDataFactory)->CreateNotificationDataWithValues(*(void**)(&initialValues), &value));
        return winrt::Windows::UI::Notifications::NotificationData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_INotificationVisual<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationVisual)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_INotificationVisual<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationVisual)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Notifications::NotificationBinding>) consume_Windows_UI_Notifications_INotificationVisual<D>::Bindings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationVisual)->get_Bindings(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Notifications::NotificationBinding>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationBinding) consume_Windows_UI_Notifications_INotificationVisual<D>::GetBinding(param::hstring const& templateName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::INotificationVisual)->GetBinding(*(void**)(&templateName), &result));
        return winrt::Windows::UI::Notifications::NotificationBinding{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->get_Content(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::DeliveryTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->get_DeliveryTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Tag(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotification)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ScheduledTileNotification) consume_Windows_UI_Notifications_IScheduledTileNotificationFactory<D>::CreateScheduledTileNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledTileNotificationFactory)->CreateScheduledTileNotification(*(void**)(&content), impl::bind_in(deliveryTime), &value));
        return winrt::Windows::UI::Notifications::ScheduledTileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_IScheduledToastNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification)->get_Content(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_UI_Notifications_IScheduledToastNotification<D>::DeliveryTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification)->get_DeliveryTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_UI_Notifications_IScheduledToastNotification<D>::SnoozeInterval() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification)->get_SnoozeInterval(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Notifications_IScheduledToastNotification<D>::MaximumSnoozeCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification)->get_MaximumSnoozeCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IScheduledToastNotification<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Tag(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification2)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification2)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Group(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification2)->put_Group(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Group() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification2)->get_Group(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::SuppressPopup(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification2)->put_SuppressPopup(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::SuppressPopup() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification2)->get_SuppressPopup(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationMirroring) consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::NotificationMirroring() const
    {
        winrt::Windows::UI::Notifications::NotificationMirroring value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification3)->get_NotificationMirroring(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::NotificationMirroring(winrt::Windows::UI::Notifications::NotificationMirroring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification3)->put_NotificationMirroring(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification3)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification3)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_IScheduledToastNotification4<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification4)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotification4<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotification4)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ScheduledToastNotification) consume_Windows_UI_Notifications_IScheduledToastNotificationFactory<D>::CreateScheduledToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory)->CreateScheduledToastNotification(*(void**)(&content), impl::bind_in(deliveryTime), &value));
        return winrt::Windows::UI::Notifications::ScheduledToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ScheduledToastNotification) consume_Windows_UI_Notifications_IScheduledToastNotificationFactory<D>::CreateScheduledToastNotificationRecurring(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime, winrt::Windows::Foundation::TimeSpan const& snoozeInterval, uint32_t maximumSnoozeCount) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory)->CreateScheduledToastNotificationRecurring(*(void**)(&content), impl::bind_in(deliveryTime), impl::bind_in(snoozeInterval), maximumSnoozeCount, &value));
        return winrt::Windows::UI::Notifications::ScheduledToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ScheduledToastNotification) consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::ScheduledToastNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->get_ScheduledToastNotification(&value));
        return winrt::Windows::UI::Notifications::ScheduledToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IShownTileNotification<D>::Arguments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IShownTileNotification)->get_Arguments(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_ITileFlyoutNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutNotification)->get_Content(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileFlyoutNotification<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutNotification)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_ITileFlyoutNotification<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutNotification)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileFlyoutNotification) consume_Windows_UI_Notifications_ITileFlyoutNotificationFactory<D>::CreateTileFlyoutNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutNotificationFactory)->CreateTileFlyoutNotification(*(void**)(&content), &value));
        return winrt::Windows::UI::Notifications::TileFlyoutNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileFlyoutUpdater) consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::CreateTileFlyoutUpdaterForApplication() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->CreateTileFlyoutUpdaterForApplication(&result));
        return winrt::Windows::UI::Notifications::TileFlyoutUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileFlyoutUpdater) consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::CreateTileFlyoutUpdaterForApplication(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->CreateTileFlyoutUpdaterForApplicationWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::TileFlyoutUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileFlyoutUpdater) consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::CreateTileFlyoutUpdaterForSecondaryTile(param::hstring const& tileId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->CreateTileFlyoutUpdaterForSecondaryTile(*(void**)(&tileId), &result));
        return winrt::Windows::UI::Notifications::TileFlyoutUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::GetTemplateContent(winrt::Windows::UI::Notifications::TileFlyoutTemplateType const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->GetTemplateContent(static_cast<int32_t>(type), &result));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::Update(winrt::Windows::UI::Notifications::TileFlyoutNotification const& notification) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdater)->Update(*(void**)(&notification)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdater)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::StartPeriodicUpdate(winrt::Windows::Foundation::Uri const& tileFlyoutContent, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdater)->StartPeriodicUpdate(*(void**)(&tileFlyoutContent), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::StartPeriodicUpdate(winrt::Windows::Foundation::Uri const& tileFlyoutContent, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdater)->StartPeriodicUpdateAtTime(*(void**)(&tileFlyoutContent), impl::bind_in(startTime), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::StopPeriodicUpdate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdater)->StopPeriodicUpdate());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationSetting) consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::Setting() const
    {
        winrt::Windows::UI::Notifications::NotificationSetting value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileFlyoutUpdater)->get_Setting(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_ITileNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileNotification)->get_Content(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileNotification<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileNotification)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_ITileNotification<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileNotification)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileNotification<D>::Tag(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileNotification)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_ITileNotification<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileNotification)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileNotification) consume_Windows_UI_Notifications_ITileNotificationFactory<D>::CreateTileNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileNotificationFactory)->CreateTileNotification(*(void**)(&content), &value));
        return winrt::Windows::UI::Notifications::TileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdater) consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::CreateTileUpdaterForApplicationForUser() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerForUser)->CreateTileUpdaterForApplication(&result));
        return winrt::Windows::UI::Notifications::TileUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdater) consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::CreateTileUpdaterForApplication(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerForUser)->CreateTileUpdaterForApplicationWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::TileUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdater) consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::CreateTileUpdaterForSecondaryTile(param::hstring const& tileId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerForUser)->CreateTileUpdaterForSecondaryTile(*(void**)(&tileId), &result));
        return winrt::Windows::UI::Notifications::TileUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerForUser)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdater) consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::CreateTileUpdaterForApplication() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerStatics)->CreateTileUpdaterForApplication(&result));
        return winrt::Windows::UI::Notifications::TileUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdater) consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::CreateTileUpdaterForApplication(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerStatics)->CreateTileUpdaterForApplicationWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::TileUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdater) consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::CreateTileUpdaterForSecondaryTile(param::hstring const& tileId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerStatics)->CreateTileUpdaterForSecondaryTile(*(void**)(&tileId), &result));
        return winrt::Windows::UI::Notifications::TileUpdater{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::GetTemplateContent(winrt::Windows::UI::Notifications::TileTemplateType const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerStatics)->GetTemplateContent(static_cast<int32_t>(type), &result));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileUpdateManagerForUser) consume_Windows_UI_Notifications_ITileUpdateManagerStatics2<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdateManagerStatics2)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::UI::Notifications::TileUpdateManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::Update(winrt::Windows::UI::Notifications::TileNotification const& notification) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->Update(*(void**)(&notification)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::EnableNotificationQueue(bool enable) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->EnableNotificationQueue(enable));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationSetting) consume_Windows_UI_Notifications_ITileUpdater<D>::Setting() const
    {
        winrt::Windows::UI::Notifications::NotificationSetting value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->get_Setting(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::AddToSchedule(winrt::Windows::UI::Notifications::ScheduledTileNotification const& scheduledTile) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->AddToSchedule(*(void**)(&scheduledTile)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::RemoveFromSchedule(winrt::Windows::UI::Notifications::ScheduledTileNotification const& scheduledTile) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->RemoveFromSchedule(*(void**)(&scheduledTile)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ScheduledTileNotification>) consume_Windows_UI_Notifications_ITileUpdater<D>::GetScheduledTileNotifications() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->GetScheduledTileNotifications(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ScheduledTileNotification>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdate(winrt::Windows::Foundation::Uri const& tileContent, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdate(*(void**)(&tileContent), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdate(winrt::Windows::Foundation::Uri const& tileContent, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdateAtTime(*(void**)(&tileContent), impl::bind_in(startTime), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::StopPeriodicUpdate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->StopPeriodicUpdate());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdateBatch(param::iterable<winrt::Windows::Foundation::Uri> const& tileContents, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdateBatch(*(void**)(&tileContents), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdateBatch(param::iterable<winrt::Windows::Foundation::Uri> const& tileContents, winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdateBatchAtTime(*(void**)(&tileContents), impl::bind_in(startTime), static_cast<int32_t>(requestedInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater2<D>::EnableNotificationQueueForSquare150x150(bool enable) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater2)->EnableNotificationQueueForSquare150x150(enable));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater2<D>::EnableNotificationQueueForWide310x150(bool enable) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater2)->EnableNotificationQueueForWide310x150(enable));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_ITileUpdater2<D>::EnableNotificationQueueForSquare310x310(bool enable) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::ITileUpdater2)->EnableNotificationQueueForSquare310x310(enable));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastActivatedEventArgs<D>::Arguments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastActivatedEventArgs)->get_Arguments(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_UI_Notifications_IToastActivatedEventArgs2<D>::UserInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastActivatedEventArgs2)->get_UserInput(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastCollection<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastCollection<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastCollection<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastCollection<D>::LaunchArgs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->get_LaunchArgs(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastCollection<D>::LaunchArgs(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->put_LaunchArgs(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Notifications_IToastCollection<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->get_Icon(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastCollection<D>::Icon(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollection)->put_Icon(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastCollection) consume_Windows_UI_Notifications_IToastCollectionFactory<D>::CreateInstance(param::hstring const& collectionId, param::hstring const& displayName, param::hstring const& launchArgs, winrt::Windows::Foundation::Uri const& iconUri) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionFactory)->CreateInstance(*(void**)(&collectionId), *(void**)(&displayName), *(void**)(&launchArgs), *(void**)(&iconUri), &value));
        return winrt::Windows::UI::Notifications::ToastCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Notifications_IToastCollectionManager<D>::SaveToastCollectionAsync(winrt::Windows::UI::Notifications::ToastCollection const& collection) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->SaveToastCollectionAsync(*(void**)(&collection), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastCollection>>) consume_Windows_UI_Notifications_IToastCollectionManager<D>::FindAllToastCollectionsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->FindAllToastCollectionsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastCollection>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastCollection>) consume_Windows_UI_Notifications_IToastCollectionManager<D>::GetToastCollectionAsync(param::hstring const& collectionId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->GetToastCollectionAsync(*(void**)(&collectionId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastCollection>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Notifications_IToastCollectionManager<D>::RemoveToastCollectionAsync(param::hstring const& collectionId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->RemoveToastCollectionAsync(*(void**)(&collectionId), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Notifications_IToastCollectionManager<D>::RemoveAllToastCollectionsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->RemoveAllToastCollectionsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_UI_Notifications_IToastCollectionManager<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastCollectionManager<D>::AppId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastCollectionManager)->get_AppId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastDismissalReason) consume_Windows_UI_Notifications_IToastDismissedEventArgs<D>::Reason() const
    {
        winrt::Windows::UI::Notifications::ToastDismissalReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastDismissedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_UI_Notifications_IToastFailedEventArgs<D>::ErrorCode() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastFailedEventArgs)->get_ErrorCode(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_IToastNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->get_Content(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification<D>::ExpirationTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->put_ExpirationTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Notifications_IToastNotification<D>::ExpirationTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->get_ExpirationTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::UI::Notifications::ToastDismissedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->add_Dismissed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed_revoker consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::UI::Notifications::ToastDismissedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Dismissed_revoker>(this, Dismissed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->remove_Dismissed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Notifications_IToastNotification<D>::Activated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->add_Activated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Notifications_IToastNotification<D>::Activated_revoker consume_Windows_UI_Notifications_IToastNotification<D>::Activated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification<D>::Activated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->remove_Activated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Notifications_IToastNotification<D>::Failed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::UI::Notifications::ToastFailedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->add_Failed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Notifications_IToastNotification<D>::Failed_revoker consume_Windows_UI_Notifications_IToastNotification<D>::Failed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::UI::Notifications::ToastFailedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Failed_revoker>(this, Failed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification<D>::Failed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification)->remove_Failed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification2<D>::Tag(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification2)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastNotification2<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification2)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification2<D>::Group(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification2)->put_Group(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastNotification2<D>::Group() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification2)->get_Group(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification2<D>::SuppressPopup(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification2)->put_SuppressPopup(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Notifications_IToastNotification2<D>::SuppressPopup() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification2)->get_SuppressPopup(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationMirroring) consume_Windows_UI_Notifications_IToastNotification3<D>::NotificationMirroring() const
    {
        winrt::Windows::UI::Notifications::NotificationMirroring value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification3)->get_NotificationMirroring(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification3<D>::NotificationMirroring(winrt::Windows::UI::Notifications::NotificationMirroring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification3)->put_NotificationMirroring(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastNotification3<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification3)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification3<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification3)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationData) consume_Windows_UI_Notifications_IToastNotification4<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification4)->get_Data(&value));
        return winrt::Windows::UI::Notifications::NotificationData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification4<D>::Data(winrt::Windows::UI::Notifications::NotificationData const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification4)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotificationPriority) consume_Windows_UI_Notifications_IToastNotification4<D>::Priority() const
    {
        winrt::Windows::UI::Notifications::ToastNotificationPriority value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification4)->get_Priority(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification4<D>::Priority(winrt::Windows::UI::Notifications::ToastNotificationPriority const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification4)->put_Priority(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Notifications_IToastNotification6<D>::ExpiresOnReboot() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification6)->get_ExpiresOnReboot(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotification6<D>::ExpiresOnReboot(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotification6)->put_ExpiresOnReboot(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastNotificationActionTriggerDetail<D>::Argument() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail)->get_Argument(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_UI_Notifications_IToastNotificationActionTriggerDetail<D>::UserInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail)->get_UserInput(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotification) consume_Windows_UI_Notifications_IToastNotificationFactory<D>::CreateToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationFactory)->CreateToastNotification(*(void**)(&content), &value));
        return winrt::Windows::UI::Notifications::ToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::RemoveGroup(param::hstring const& group) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroup(*(void**)(&group)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::RemoveGroup(param::hstring const& group, param::hstring const& applicationId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroupWithId(*(void**)(&group), *(void**)(&applicationId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Remove(param::hstring const& tag, param::hstring const& group, param::hstring const& applicationId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroupedTagWithId(*(void**)(&tag), *(void**)(&group), *(void**)(&applicationId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Remove(param::hstring const& tag, param::hstring const& group) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroupedTag(*(void**)(&tag), *(void**)(&group)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Remove(param::hstring const& tag) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->Remove(*(void**)(&tag)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Clear(param::hstring const& applicationId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory)->ClearWithId(*(void**)(&applicationId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastNotification>) consume_Windows_UI_Notifications_IToastNotificationHistory2<D>::GetHistory() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory2)->GetHistory(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastNotification>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastNotification>) consume_Windows_UI_Notifications_IToastNotificationHistory2<D>::GetHistory(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistory2)->GetHistoryWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastNotification>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastHistoryChangedType) consume_Windows_UI_Notifications_IToastNotificationHistoryChangedTriggerDetail<D>::ChangeType() const
    {
        winrt::Windows::UI::Notifications::ToastHistoryChangedType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail)->get_ChangeType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Notifications_IToastNotificationHistoryChangedTriggerDetail2<D>::CollectionId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2)->get_CollectionId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotifier) consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::CreateToastNotifier() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser)->CreateToastNotifier(&result));
        return winrt::Windows::UI::Notifications::ToastNotifier{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotifier) consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::CreateToastNotifier(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser)->CreateToastNotifierWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::ToastNotifier{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotificationHistory) consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::History() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser)->get_History(&value));
        return winrt::Windows::UI::Notifications::ToastNotificationHistory{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastNotifier>) consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetToastNotifierForToastCollectionIdAsync(param::hstring const& collectionId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetToastNotifierForToastCollectionIdAsync(*(void**)(&collectionId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastNotifier>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastNotificationHistory>) consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetHistoryForToastCollectionIdAsync(param::hstring const& collectionId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetHistoryForToastCollectionIdAsync(*(void**)(&collectionId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastNotificationHistory>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastCollectionManager) consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetToastCollectionManager() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetToastCollectionManager(&result));
        return winrt::Windows::UI::Notifications::ToastCollectionManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastCollectionManager) consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetToastCollectionManager(param::hstring const& appId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetToastCollectionManagerWithAppId(*(void**)(&appId), &result));
        return winrt::Windows::UI::Notifications::ToastCollectionManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotificationMode) consume_Windows_UI_Notifications_IToastNotificationManagerForUser3<D>::NotificationMode() const
    {
        winrt::Windows::UI::Notifications::ToastNotificationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3)->get_NotificationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Notifications_IToastNotificationManagerForUser3<D>::NotificationModeChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3)->add_NotificationModeChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Notifications_IToastNotificationManagerForUser3<D>::NotificationModeChanged_revoker consume_Windows_UI_Notifications_IToastNotificationManagerForUser3<D>::NotificationModeChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, NotificationModeChanged_revoker>(this, NotificationModeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationManagerForUser3<D>::NotificationModeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3)->remove_NotificationModeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotifier) consume_Windows_UI_Notifications_IToastNotificationManagerStatics<D>::CreateToastNotifier() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics)->CreateToastNotifier(&result));
        return winrt::Windows::UI::Notifications::ToastNotifier{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotifier) consume_Windows_UI_Notifications_IToastNotificationManagerStatics<D>::CreateToastNotifier(param::hstring const& applicationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics)->CreateToastNotifierWithId(*(void**)(&applicationId), &result));
        return winrt::Windows::UI::Notifications::ToastNotifier{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_UI_Notifications_IToastNotificationManagerStatics<D>::GetTemplateContent(winrt::Windows::UI::Notifications::ToastTemplateType const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics)->GetTemplateContent(static_cast<int32_t>(type), &result));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotificationHistory) consume_Windows_UI_Notifications_IToastNotificationManagerStatics2<D>::History() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics2)->get_History(&value));
        return winrt::Windows::UI::Notifications::ToastNotificationHistory{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotificationManagerForUser) consume_Windows_UI_Notifications_IToastNotificationManagerStatics4<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::UI::Notifications::ToastNotificationManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotificationManagerStatics4<D>::ConfigureNotificationMirroring(winrt::Windows::UI::Notifications::NotificationMirroring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4)->ConfigureNotificationMirroring(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotificationManagerForUser) consume_Windows_UI_Notifications_IToastNotificationManagerStatics5<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotificationManagerStatics5)->GetDefault(&result));
        return winrt::Windows::UI::Notifications::ToastNotificationManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotifier<D>::Show(winrt::Windows::UI::Notifications::ToastNotification const& notification) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier)->Show(*(void**)(&notification)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotifier<D>::Hide(winrt::Windows::UI::Notifications::ToastNotification const& notification) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier)->Hide(*(void**)(&notification)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationSetting) consume_Windows_UI_Notifications_IToastNotifier<D>::Setting() const
    {
        winrt::Windows::UI::Notifications::NotificationSetting value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier)->get_Setting(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotifier<D>::AddToSchedule(winrt::Windows::UI::Notifications::ScheduledToastNotification const& scheduledToast) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier)->AddToSchedule(*(void**)(&scheduledToast)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotifier<D>::RemoveFromSchedule(winrt::Windows::UI::Notifications::ScheduledToastNotification const& scheduledToast) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier)->RemoveFromSchedule(*(void**)(&scheduledToast)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ScheduledToastNotification>) consume_Windows_UI_Notifications_IToastNotifier<D>::GetScheduledToastNotifications() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier)->GetScheduledToastNotifications(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ScheduledToastNotification>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationUpdateResult) consume_Windows_UI_Notifications_IToastNotifier2<D>::Update(winrt::Windows::UI::Notifications::NotificationData const& data, param::hstring const& tag, param::hstring const& group) const
    {
        winrt::Windows::UI::Notifications::NotificationUpdateResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier2)->UpdateWithTagAndGroup(*(void**)(&data), *(void**)(&tag), *(void**)(&group), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::NotificationUpdateResult) consume_Windows_UI_Notifications_IToastNotifier2<D>::Update(winrt::Windows::UI::Notifications::NotificationData const& data, param::hstring const& tag) const
    {
        winrt::Windows::UI::Notifications::NotificationUpdateResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier2)->UpdateWithTag(*(void**)(&data), *(void**)(&tag), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotifier, winrt::Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier3)->add_ScheduledToastNotificationShowing(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing_revoker consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotifier, winrt::Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ScheduledToastNotificationShowing_revoker>(this, ScheduledToastNotificationShowing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IToastNotifier3)->remove_ScheduledToastNotificationShowing(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::Notification) consume_Windows_UI_Notifications_IUserNotification<D>::Notification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IUserNotification)->get_Notification(&value));
        return winrt::Windows::UI::Notifications::Notification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppInfo) consume_Windows_UI_Notifications_IUserNotification<D>::AppInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IUserNotification)->get_AppInfo(&value));
        return winrt::Windows::ApplicationModel::AppInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Notifications_IUserNotification<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IUserNotification)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_UI_Notifications_IUserNotification<D>::CreationTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IUserNotification)->get_CreationTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::UserNotificationChangedKind) consume_Windows_UI_Notifications_IUserNotificationChangedEventArgs<D>::ChangeKind() const
    {
        winrt::Windows::UI::Notifications::UserNotificationChangedKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs)->get_ChangeKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Notifications_IUserNotificationChangedEventArgs<D>::UserNotificationId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs)->get_UserNotificationId(&value));
        return value;
    }
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IAdaptiveNotificationContent> : produce_base<D, winrt::Windows::UI::Notifications::IAdaptiveNotificationContent>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::AdaptiveNotificationContentKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hints(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Hints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IAdaptiveNotificationText> : produce_base<D, winrt::Windows::UI::Notifications::IAdaptiveNotificationText>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IBadgeNotification> : produce_base<D, winrt::Windows::UI::Notifications::IBadgeNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IBadgeNotificationFactory> : produce_base<D, winrt::Windows::UI::Notifications::IBadgeNotificationFactory>
    {
        int32_t __stdcall CreateBadgeNotification(void* content, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::BadgeNotification>(this->shim().CreateBadgeNotification(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser> : produce_base<D, winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser>
    {
        int32_t __stdcall CreateBadgeUpdaterForApplication(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBadgeUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBadgeUpdaterForSecondaryTile(void* tileId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics> : produce_base<D, winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics>
    {
        int32_t __stdcall CreateBadgeUpdaterForApplication(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBadgeUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBadgeUpdaterForSecondaryTile(void* tileId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTemplateContent(int32_t type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<winrt::Windows::UI::Notifications::BadgeTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics2> : produce_base<D, winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics2>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::BadgeUpdateManagerForUser>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IBadgeUpdater> : produce_base<D, winrt::Windows::UI::Notifications::IBadgeUpdater>
    {
        int32_t __stdcall Update(void* notification) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Update(*reinterpret_cast<winrt::Windows::UI::Notifications::BadgeNotification const*>(&notification));
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
        int32_t __stdcall StartPeriodicUpdate(void* badgeContent, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&badgeContent), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPeriodicUpdateAtTime(void* badgeContent, int64_t startTime, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&badgeContent), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopPeriodicUpdate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPeriodicUpdate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics> : produce_base<D, winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>
    {
        int32_t __stdcall get_Style(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Style());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Wrap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Wrap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxLines(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinLines(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MinLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextStacking(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TextStacking());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Align(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Align());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics> : produce_base<D, winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>
    {
        int32_t __stdcall get_Caption(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Body(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Base(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Base());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subtitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subtitle());
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
        int32_t __stdcall get_Subheader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subheader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Header(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Header());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TitleNumeral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TitleNumeral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubheaderNumeral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SubheaderNumeral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderNumeral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HeaderNumeral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CaptionSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CaptionSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BodySubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BodySubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BaseSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubtitleSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SubtitleSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TitleSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TitleSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubheaderSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SubheaderSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubheaderNumeralSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SubheaderNumeralSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HeaderSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderNumeralSubtle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HeaderNumeralSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IKnownNotificationBindingsStatics> : produce_base<D, winrt::Windows::UI::Notifications::IKnownNotificationBindingsStatics>
    {
        int32_t __stdcall get_ToastGeneric(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ToastGeneric());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::INotification> : produce_base<D, winrt::Windows::UI::Notifications::INotification>
    {
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Visual(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationVisual>(this->shim().Visual());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Visual(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Visual(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationVisual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::INotificationBinding> : produce_base<D, winrt::Windows::UI::Notifications::INotificationBinding>
    {
        int32_t __stdcall get_Template(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Template(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Template(*reinterpret_cast<hstring const*>(&value));
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
        int32_t __stdcall get_Hints(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Hints());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTextElements(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::AdaptiveNotificationText>>(this->shim().GetTextElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::INotificationData> : produce_base<D, winrt::Windows::UI::Notifications::INotificationData>
    {
        int32_t __stdcall get_Values(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SequenceNumber(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SequenceNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SequenceNumber(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SequenceNumber(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::INotificationDataFactory> : produce_base<D, winrt::Windows::UI::Notifications::INotificationDataFactory>
    {
        int32_t __stdcall CreateNotificationDataWithValuesAndSequenceNumber(void* initialValues, uint32_t sequenceNumber, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationData>(this->shim().CreateNotificationData(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&initialValues), sequenceNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNotificationDataWithValues(void* initialValues, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationData>(this->shim().CreateNotificationData(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&initialValues)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::INotificationVisual> : produce_base<D, winrt::Windows::UI::Notifications::INotificationVisual>
    {
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
        int32_t __stdcall get_Bindings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Notifications::NotificationBinding>>(this->shim().Bindings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBinding(void* templateName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::NotificationBinding>(this->shim().GetBinding(*reinterpret_cast<hstring const*>(&templateName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledTileNotification> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledTileNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeliveryTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().DeliveryTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledTileNotificationFactory> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledTileNotificationFactory>
    {
        int32_t __stdcall CreateScheduledTileNotification(void* content, int64_t deliveryTime, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ScheduledTileNotification>(this->shim().CreateScheduledTileNotification(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&deliveryTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledToastNotification> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledToastNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeliveryTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().DeliveryTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SnoozeInterval(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().SnoozeInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaximumSnoozeCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaximumSnoozeCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledToastNotification2> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledToastNotification2>
    {
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Group(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Group(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Group(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuppressPopup(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuppressPopup(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuppressPopup(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SuppressPopup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledToastNotification3> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledToastNotification3>
    {
        int32_t __stdcall get_NotificationMirroring(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationMirroring>(this->shim().NotificationMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NotificationMirroring(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotificationMirroring(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationMirroring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledToastNotification4> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledToastNotification4>
    {
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory>
    {
        int32_t __stdcall CreateScheduledToastNotification(void* content, int64_t deliveryTime, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ScheduledToastNotification>(this->shim().CreateScheduledToastNotification(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&deliveryTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateScheduledToastNotificationRecurring(void* content, int64_t deliveryTime, int64_t snoozeInterval, uint32_t maximumSnoozeCount, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ScheduledToastNotification>(this->shim().CreateScheduledToastNotificationRecurring(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&deliveryTime), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&snoozeInterval), maximumSnoozeCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs> : produce_base<D, winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs>
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
        int32_t __stdcall get_ScheduledToastNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ScheduledToastNotification>(this->shim().ScheduledToastNotification());
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
    struct produce<D, winrt::Windows::UI::Notifications::IShownTileNotification> : produce_base<D, winrt::Windows::UI::Notifications::IShownTileNotification>
    {
        int32_t __stdcall get_Arguments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileFlyoutNotification> : produce_base<D, winrt::Windows::UI::Notifications::ITileFlyoutNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileFlyoutNotificationFactory> : produce_base<D, winrt::Windows::UI::Notifications::ITileFlyoutNotificationFactory>
    {
        int32_t __stdcall CreateTileFlyoutNotification(void* content, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileFlyoutNotification>(this->shim().CreateTileFlyoutNotification(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics> : produce_base<D, winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics>
    {
        int32_t __stdcall CreateTileFlyoutUpdaterForApplication(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileFlyoutUpdater>(this->shim().CreateTileFlyoutUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTileFlyoutUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileFlyoutUpdater>(this->shim().CreateTileFlyoutUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTileFlyoutUpdaterForSecondaryTile(void* tileId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileFlyoutUpdater>(this->shim().CreateTileFlyoutUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTemplateContent(int32_t type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<winrt::Windows::UI::Notifications::TileFlyoutTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileFlyoutUpdater> : produce_base<D, winrt::Windows::UI::Notifications::ITileFlyoutUpdater>
    {
        int32_t __stdcall Update(void* notification) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Update(*reinterpret_cast<winrt::Windows::UI::Notifications::TileFlyoutNotification const*>(&notification));
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
        int32_t __stdcall StartPeriodicUpdate(void* tileFlyoutContent, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&tileFlyoutContent), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPeriodicUpdateAtTime(void* tileFlyoutContent, int64_t startTime, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&tileFlyoutContent), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopPeriodicUpdate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPeriodicUpdate();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Setting(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationSetting>(this->shim().Setting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileNotification> : produce_base<D, winrt::Windows::UI::Notifications::ITileNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileNotificationFactory> : produce_base<D, winrt::Windows::UI::Notifications::ITileNotificationFactory>
    {
        int32_t __stdcall CreateTileNotification(void* content, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileNotification>(this->shim().CreateTileNotification(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileUpdateManagerForUser> : produce_base<D, winrt::Windows::UI::Notifications::ITileUpdateManagerForUser>
    {
        int32_t __stdcall CreateTileUpdaterForApplication(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplicationForUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTileUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTileUpdaterForSecondaryTile(void* tileId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileUpdateManagerStatics> : produce_base<D, winrt::Windows::UI::Notifications::ITileUpdateManagerStatics>
    {
        int32_t __stdcall CreateTileUpdaterForApplication(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTileUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTileUpdaterForSecondaryTile(void* tileId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTemplateContent(int32_t type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<winrt::Windows::UI::Notifications::TileTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileUpdateManagerStatics2> : produce_base<D, winrt::Windows::UI::Notifications::ITileUpdateManagerStatics2>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::TileUpdateManagerForUser>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileUpdater> : produce_base<D, winrt::Windows::UI::Notifications::ITileUpdater>
    {
        int32_t __stdcall Update(void* notification) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Update(*reinterpret_cast<winrt::Windows::UI::Notifications::TileNotification const*>(&notification));
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
        int32_t __stdcall EnableNotificationQueue(bool enable) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableNotificationQueue(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Setting(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationSetting>(this->shim().Setting());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToSchedule(void* scheduledTile) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToSchedule(*reinterpret_cast<winrt::Windows::UI::Notifications::ScheduledTileNotification const*>(&scheduledTile));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveFromSchedule(void* scheduledTile) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveFromSchedule(*reinterpret_cast<winrt::Windows::UI::Notifications::ScheduledTileNotification const*>(&scheduledTile));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScheduledTileNotifications(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ScheduledTileNotification>>(this->shim().GetScheduledTileNotifications());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPeriodicUpdate(void* tileContent, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&tileContent), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPeriodicUpdateAtTime(void* tileContent, int64_t startTime, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&tileContent), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopPeriodicUpdate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPeriodicUpdate();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPeriodicUpdateBatch(void* tileContents, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdateBatch(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Uri> const*>(&tileContents), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPeriodicUpdateBatchAtTime(void* tileContents, int64_t startTime, int32_t requestedInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPeriodicUpdateBatch(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Uri> const*>(&tileContents), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<winrt::Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::ITileUpdater2> : produce_base<D, winrt::Windows::UI::Notifications::ITileUpdater2>
    {
        int32_t __stdcall EnableNotificationQueueForSquare150x150(bool enable) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableNotificationQueueForSquare150x150(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableNotificationQueueForWide310x150(bool enable) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableNotificationQueueForWide310x150(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableNotificationQueueForSquare310x310(bool enable) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableNotificationQueueForSquare310x310(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastActivatedEventArgs> : produce_base<D, winrt::Windows::UI::Notifications::IToastActivatedEventArgs>
    {
        int32_t __stdcall get_Arguments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastActivatedEventArgs2> : produce_base<D, winrt::Windows::UI::Notifications::IToastActivatedEventArgs2>
    {
        int32_t __stdcall get_UserInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().UserInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastCollection> : produce_base<D, winrt::Windows::UI::Notifications::IToastCollection>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LaunchArgs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LaunchArgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LaunchArgs(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LaunchArgs(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Icon(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Icon(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastCollectionFactory> : produce_base<D, winrt::Windows::UI::Notifications::IToastCollectionFactory>
    {
        int32_t __stdcall CreateInstance(void* collectionId, void* displayName, void* launchArgs, void* iconUri, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastCollection>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&collectionId), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&launchArgs), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&iconUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastCollectionManager> : produce_base<D, winrt::Windows::UI::Notifications::IToastCollectionManager>
    {
        int32_t __stdcall SaveToastCollectionAsync(void* collection, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveToastCollectionAsync(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastCollection const*>(&collection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllToastCollectionsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastCollection>>>(this->shim().FindAllToastCollectionsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetToastCollectionAsync(void* collectionId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastCollection>>(this->shim().GetToastCollectionAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveToastCollectionAsync(void* collectionId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RemoveToastCollectionAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveAllToastCollectionsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RemoveAllToastCollectionsAsync());
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
        int32_t __stdcall get_AppId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastDismissedEventArgs> : produce_base<D, winrt::Windows::UI::Notifications::IToastDismissedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastDismissalReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastFailedEventArgs> : produce_base<D, winrt::Windows::UI::Notifications::IToastFailedEventArgs>
    {
        int32_t __stdcall get_ErrorCode(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotification> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Dismissed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Dismissed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::UI::Notifications::ToastDismissedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Dismissed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Dismissed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Activated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Activated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Failed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Failed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotification, winrt::Windows::UI::Notifications::ToastFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Failed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Failed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotification2> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotification2>
    {
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Group(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Group(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Group(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuppressPopup(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuppressPopup(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuppressPopup(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SuppressPopup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotification3> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotification3>
    {
        int32_t __stdcall get_NotificationMirroring(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationMirroring>(this->shim().NotificationMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NotificationMirroring(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotificationMirroring(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationMirroring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotification4> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotification4>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationData>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationData const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Priority(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotificationPriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Priority(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Priority(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotificationPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotification6> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotification6>
    {
        int32_t __stdcall get_ExpiresOnReboot(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ExpiresOnReboot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpiresOnReboot(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpiresOnReboot(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail>
    {
        int32_t __stdcall get_Argument(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Argument());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().UserInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationFactory> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationFactory>
    {
        int32_t __stdcall CreateToastNotification(void* content, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotification>(this->shim().CreateToastNotification(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationHistory> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationHistory>
    {
        int32_t __stdcall RemoveGroup(void* group) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveGroup(*reinterpret_cast<hstring const*>(&group));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveGroupWithId(void* group, void* applicationId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveGroup(*reinterpret_cast<hstring const*>(&group), *reinterpret_cast<hstring const*>(&applicationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveGroupedTagWithId(void* tag, void* group, void* applicationId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<hstring const*>(&group), *reinterpret_cast<hstring const*>(&applicationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveGroupedTag(void* tag, void* group) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<hstring const*>(&group));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Remove(void* tag) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<hstring const*>(&tag));
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
        int32_t __stdcall ClearWithId(void* applicationId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear(*reinterpret_cast<hstring const*>(&applicationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationHistory2> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationHistory2>
    {
        int32_t __stdcall GetHistory(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastNotification>>(this->shim().GetHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHistoryWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ToastNotification>>(this->shim().GetHistory(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail>
    {
        int32_t __stdcall get_ChangeType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastHistoryChangedType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2>
    {
        int32_t __stdcall get_CollectionId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CollectionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser>
    {
        int32_t __stdcall CreateToastNotifier(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateToastNotifierWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_History(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotificationHistory>(this->shim().History());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2>
    {
        int32_t __stdcall GetToastNotifierForToastCollectionIdAsync(void* collectionId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastNotifier>>(this->shim().GetToastNotifierForToastCollectionIdAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHistoryForToastCollectionIdAsync(void* collectionId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::ToastNotificationHistory>>(this->shim().GetHistoryForToastCollectionIdAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetToastCollectionManager(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastCollectionManager>(this->shim().GetToastCollectionManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetToastCollectionManagerWithAppId(void* appId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastCollectionManager>(this->shim().GetToastCollectionManager(*reinterpret_cast<hstring const*>(&appId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3>
    {
        int32_t __stdcall get_NotificationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotificationMode>(this->shim().NotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_NotificationModeChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NotificationModeChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NotificationModeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotificationModeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics>
    {
        int32_t __stdcall CreateToastNotifier(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateToastNotifierWithId(void* applicationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTemplateContent(int32_t type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics2> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics2>
    {
        int32_t __stdcall get_History(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotificationHistory>(this->shim().History());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureNotificationMirroring(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureNotificationMirroring(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationMirroring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics5> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotificationManagerStatics5>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotifier> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotifier>
    {
        int32_t __stdcall Show(void* notification) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Show(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Hide(void* notification) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hide(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Setting(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::NotificationSetting>(this->shim().Setting());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToSchedule(void* scheduledToast) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToSchedule(*reinterpret_cast<winrt::Windows::UI::Notifications::ScheduledToastNotification const*>(&scheduledToast));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveFromSchedule(void* scheduledToast) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveFromSchedule(*reinterpret_cast<winrt::Windows::UI::Notifications::ScheduledToastNotification const*>(&scheduledToast));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScheduledToastNotifications(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::ScheduledToastNotification>>(this->shim().GetScheduledToastNotifications());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotifier2> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotifier2>
    {
        int32_t __stdcall UpdateWithTagAndGroup(void* data, void* tag, void* group, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::NotificationUpdateResult>(this->shim().Update(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationData const*>(&data), *reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<hstring const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateWithTag(void* data, void* tag, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::NotificationUpdateResult>(this->shim().Update(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationData const*>(&data), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IToastNotifier3> : produce_base<D, winrt::Windows::UI::Notifications::IToastNotifier3>
    {
        int32_t __stdcall add_ScheduledToastNotificationShowing(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ScheduledToastNotificationShowing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::ToastNotifier, winrt::Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ScheduledToastNotificationShowing(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScheduledToastNotificationShowing(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IUserNotification> : produce_base<D, winrt::Windows::UI::Notifications::IUserNotification>
    {
        int32_t __stdcall get_Notification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::Notification>(this->shim().Notification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppInfo>(this->shim().AppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CreationTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().CreationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs> : produce_base<D, winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs>
    {
        int32_t __stdcall get_ChangeKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::UserNotificationChangedKind>(this->shim().ChangeKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserNotificationId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UserNotificationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Notifications
{
    constexpr auto operator|(NotificationKinds const left, NotificationKinds const right) noexcept
    {
        return static_cast<NotificationKinds>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(NotificationKinds& left, NotificationKinds const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(NotificationKinds const left, NotificationKinds const right) noexcept
    {
        return static_cast<NotificationKinds>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(NotificationKinds& left, NotificationKinds const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(NotificationKinds const value) noexcept
    {
        return static_cast<NotificationKinds>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(NotificationKinds const left, NotificationKinds const right) noexcept
    {
        return static_cast<NotificationKinds>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(NotificationKinds& left, NotificationKinds const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline AdaptiveNotificationText::AdaptiveNotificationText() :
        AdaptiveNotificationText(impl::call_factory_cast<AdaptiveNotificationText(*)(winrt::Windows::Foundation::IActivationFactory const&), AdaptiveNotificationText>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AdaptiveNotificationText>(); }))
    {
    }
    inline BadgeNotification::BadgeNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) :
        BadgeNotification(impl::call_factory<BadgeNotification, IBadgeNotificationFactory>([&](IBadgeNotificationFactory const& f) { return f.CreateBadgeNotification(content); }))
    {
    }
    inline auto BadgeUpdateManager::CreateBadgeUpdaterForApplication()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::BadgeUpdater(*)(IBadgeUpdateManagerStatics const&), BadgeUpdateManager, IBadgeUpdateManagerStatics>([](IBadgeUpdateManagerStatics const& f) { return f.CreateBadgeUpdaterForApplication(); });
    }
    inline auto BadgeUpdateManager::CreateBadgeUpdaterForApplication(param::hstring const& applicationId)
    {
        return impl::call_factory<BadgeUpdateManager, IBadgeUpdateManagerStatics>([&](IBadgeUpdateManagerStatics const& f) { return f.CreateBadgeUpdaterForApplication(applicationId); });
    }
    inline auto BadgeUpdateManager::CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId)
    {
        return impl::call_factory<BadgeUpdateManager, IBadgeUpdateManagerStatics>([&](IBadgeUpdateManagerStatics const& f) { return f.CreateBadgeUpdaterForSecondaryTile(tileId); });
    }
    inline auto BadgeUpdateManager::GetTemplateContent(winrt::Windows::UI::Notifications::BadgeTemplateType const& type)
    {
        return impl::call_factory<BadgeUpdateManager, IBadgeUpdateManagerStatics>([&](IBadgeUpdateManagerStatics const& f) { return f.GetTemplateContent(type); });
    }
    inline auto BadgeUpdateManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<BadgeUpdateManager, IBadgeUpdateManagerStatics2>([&](IBadgeUpdateManagerStatics2 const& f) { return f.GetForUser(user); });
    }
    inline auto KnownAdaptiveNotificationHints::Style()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationHintsStatics const&), KnownAdaptiveNotificationHints, IKnownAdaptiveNotificationHintsStatics>([](IKnownAdaptiveNotificationHintsStatics const& f) { return f.Style(); });
    }
    inline auto KnownAdaptiveNotificationHints::Wrap()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationHintsStatics const&), KnownAdaptiveNotificationHints, IKnownAdaptiveNotificationHintsStatics>([](IKnownAdaptiveNotificationHintsStatics const& f) { return f.Wrap(); });
    }
    inline auto KnownAdaptiveNotificationHints::MaxLines()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationHintsStatics const&), KnownAdaptiveNotificationHints, IKnownAdaptiveNotificationHintsStatics>([](IKnownAdaptiveNotificationHintsStatics const& f) { return f.MaxLines(); });
    }
    inline auto KnownAdaptiveNotificationHints::MinLines()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationHintsStatics const&), KnownAdaptiveNotificationHints, IKnownAdaptiveNotificationHintsStatics>([](IKnownAdaptiveNotificationHintsStatics const& f) { return f.MinLines(); });
    }
    inline auto KnownAdaptiveNotificationHints::TextStacking()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationHintsStatics const&), KnownAdaptiveNotificationHints, IKnownAdaptiveNotificationHintsStatics>([](IKnownAdaptiveNotificationHintsStatics const& f) { return f.TextStacking(); });
    }
    inline auto KnownAdaptiveNotificationHints::Align()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationHintsStatics const&), KnownAdaptiveNotificationHints, IKnownAdaptiveNotificationHintsStatics>([](IKnownAdaptiveNotificationHintsStatics const& f) { return f.Align(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Caption()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Caption(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Body()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Body(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Base()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Base(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Subtitle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Subtitle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Title()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Title(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Subheader()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Subheader(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::Header()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.Header(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::TitleNumeral()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.TitleNumeral(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::SubheaderNumeral()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.SubheaderNumeral(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::HeaderNumeral()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.HeaderNumeral(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::CaptionSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.CaptionSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::BodySubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.BodySubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::BaseSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.BaseSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::SubtitleSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.SubtitleSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::TitleSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.TitleSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::SubheaderSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.SubheaderSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::SubheaderNumeralSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.SubheaderNumeralSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::HeaderSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.HeaderSubtle(); });
    }
    inline auto KnownAdaptiveNotificationTextStyles::HeaderNumeralSubtle()
    {
        return impl::call_factory_cast<hstring(*)(IKnownAdaptiveNotificationTextStylesStatics const&), KnownAdaptiveNotificationTextStyles, IKnownAdaptiveNotificationTextStylesStatics>([](IKnownAdaptiveNotificationTextStylesStatics const& f) { return f.HeaderNumeralSubtle(); });
    }
    inline auto KnownNotificationBindings::ToastGeneric()
    {
        return impl::call_factory_cast<hstring(*)(IKnownNotificationBindingsStatics const&), KnownNotificationBindings, IKnownNotificationBindingsStatics>([](IKnownNotificationBindingsStatics const& f) { return f.ToastGeneric(); });
    }
    inline Notification::Notification() :
        Notification(impl::call_factory_cast<Notification(*)(winrt::Windows::Foundation::IActivationFactory const&), Notification>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Notification>(); }))
    {
    }
    inline NotificationData::NotificationData() :
        NotificationData(impl::call_factory_cast<NotificationData(*)(winrt::Windows::Foundation::IActivationFactory const&), NotificationData>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NotificationData>(); }))
    {
    }
    inline NotificationData::NotificationData(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues, uint32_t sequenceNumber) :
        NotificationData(impl::call_factory<NotificationData, INotificationDataFactory>([&](INotificationDataFactory const& f) { return f.CreateNotificationData(initialValues, sequenceNumber); }))
    {
    }
    inline NotificationData::NotificationData(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues) :
        NotificationData(impl::call_factory<NotificationData, INotificationDataFactory>([&](INotificationDataFactory const& f) { return f.CreateNotificationData(initialValues); }))
    {
    }
    inline ScheduledTileNotification::ScheduledTileNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime) :
        ScheduledTileNotification(impl::call_factory<ScheduledTileNotification, IScheduledTileNotificationFactory>([&](IScheduledTileNotificationFactory const& f) { return f.CreateScheduledTileNotification(content, deliveryTime); }))
    {
    }
    inline ScheduledToastNotification::ScheduledToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime) :
        ScheduledToastNotification(impl::call_factory<ScheduledToastNotification, IScheduledToastNotificationFactory>([&](IScheduledToastNotificationFactory const& f) { return f.CreateScheduledToastNotification(content, deliveryTime); }))
    {
    }
    inline ScheduledToastNotification::ScheduledToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content, winrt::Windows::Foundation::DateTime const& deliveryTime, winrt::Windows::Foundation::TimeSpan const& snoozeInterval, uint32_t maximumSnoozeCount) :
        ScheduledToastNotification(impl::call_factory<ScheduledToastNotification, IScheduledToastNotificationFactory>([&](IScheduledToastNotificationFactory const& f) { return f.CreateScheduledToastNotificationRecurring(content, deliveryTime, snoozeInterval, maximumSnoozeCount); }))
    {
    }
    inline TileFlyoutNotification::TileFlyoutNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) :
        TileFlyoutNotification(impl::call_factory<TileFlyoutNotification, ITileFlyoutNotificationFactory>([&](ITileFlyoutNotificationFactory const& f) { return f.CreateTileFlyoutNotification(content); }))
    {
    }
    inline auto TileFlyoutUpdateManager::CreateTileFlyoutUpdaterForApplication()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::TileFlyoutUpdater(*)(ITileFlyoutUpdateManagerStatics const&), TileFlyoutUpdateManager, ITileFlyoutUpdateManagerStatics>([](ITileFlyoutUpdateManagerStatics const& f) { return f.CreateTileFlyoutUpdaterForApplication(); });
    }
    inline auto TileFlyoutUpdateManager::CreateTileFlyoutUpdaterForApplication(param::hstring const& applicationId)
    {
        return impl::call_factory<TileFlyoutUpdateManager, ITileFlyoutUpdateManagerStatics>([&](ITileFlyoutUpdateManagerStatics const& f) { return f.CreateTileFlyoutUpdaterForApplication(applicationId); });
    }
    inline auto TileFlyoutUpdateManager::CreateTileFlyoutUpdaterForSecondaryTile(param::hstring const& tileId)
    {
        return impl::call_factory<TileFlyoutUpdateManager, ITileFlyoutUpdateManagerStatics>([&](ITileFlyoutUpdateManagerStatics const& f) { return f.CreateTileFlyoutUpdaterForSecondaryTile(tileId); });
    }
    inline auto TileFlyoutUpdateManager::GetTemplateContent(winrt::Windows::UI::Notifications::TileFlyoutTemplateType const& type)
    {
        return impl::call_factory<TileFlyoutUpdateManager, ITileFlyoutUpdateManagerStatics>([&](ITileFlyoutUpdateManagerStatics const& f) { return f.GetTemplateContent(type); });
    }
    inline TileNotification::TileNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) :
        TileNotification(impl::call_factory<TileNotification, ITileNotificationFactory>([&](ITileNotificationFactory const& f) { return f.CreateTileNotification(content); }))
    {
    }
    inline auto TileUpdateManager::CreateTileUpdaterForApplication()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::TileUpdater(*)(ITileUpdateManagerStatics const&), TileUpdateManager, ITileUpdateManagerStatics>([](ITileUpdateManagerStatics const& f) { return f.CreateTileUpdaterForApplication(); });
    }
    inline auto TileUpdateManager::CreateTileUpdaterForApplication(param::hstring const& applicationId)
    {
        return impl::call_factory<TileUpdateManager, ITileUpdateManagerStatics>([&](ITileUpdateManagerStatics const& f) { return f.CreateTileUpdaterForApplication(applicationId); });
    }
    inline auto TileUpdateManager::CreateTileUpdaterForSecondaryTile(param::hstring const& tileId)
    {
        return impl::call_factory<TileUpdateManager, ITileUpdateManagerStatics>([&](ITileUpdateManagerStatics const& f) { return f.CreateTileUpdaterForSecondaryTile(tileId); });
    }
    inline auto TileUpdateManager::GetTemplateContent(winrt::Windows::UI::Notifications::TileTemplateType const& type)
    {
        return impl::call_factory<TileUpdateManager, ITileUpdateManagerStatics>([&](ITileUpdateManagerStatics const& f) { return f.GetTemplateContent(type); });
    }
    inline auto TileUpdateManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<TileUpdateManager, ITileUpdateManagerStatics2>([&](ITileUpdateManagerStatics2 const& f) { return f.GetForUser(user); });
    }
    inline ToastCollection::ToastCollection(param::hstring const& collectionId, param::hstring const& displayName, param::hstring const& launchArgs, winrt::Windows::Foundation::Uri const& iconUri) :
        ToastCollection(impl::call_factory<ToastCollection, IToastCollectionFactory>([&](IToastCollectionFactory const& f) { return f.CreateInstance(collectionId, displayName, launchArgs, iconUri); }))
    {
    }
    inline ToastNotification::ToastNotification(winrt::Windows::Data::Xml::Dom::XmlDocument const& content) :
        ToastNotification(impl::call_factory<ToastNotification, IToastNotificationFactory>([&](IToastNotificationFactory const& f) { return f.CreateToastNotification(content); }))
    {
    }
    inline auto ToastNotificationManager::CreateToastNotifier()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::ToastNotifier(*)(IToastNotificationManagerStatics const&), ToastNotificationManager, IToastNotificationManagerStatics>([](IToastNotificationManagerStatics const& f) { return f.CreateToastNotifier(); });
    }
    inline auto ToastNotificationManager::CreateToastNotifier(param::hstring const& applicationId)
    {
        return impl::call_factory<ToastNotificationManager, IToastNotificationManagerStatics>([&](IToastNotificationManagerStatics const& f) { return f.CreateToastNotifier(applicationId); });
    }
    inline auto ToastNotificationManager::GetTemplateContent(winrt::Windows::UI::Notifications::ToastTemplateType const& type)
    {
        return impl::call_factory<ToastNotificationManager, IToastNotificationManagerStatics>([&](IToastNotificationManagerStatics const& f) { return f.GetTemplateContent(type); });
    }
    inline auto ToastNotificationManager::History()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::ToastNotificationHistory(*)(IToastNotificationManagerStatics2 const&), ToastNotificationManager, IToastNotificationManagerStatics2>([](IToastNotificationManagerStatics2 const& f) { return f.History(); });
    }
    inline auto ToastNotificationManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<ToastNotificationManager, IToastNotificationManagerStatics4>([&](IToastNotificationManagerStatics4 const& f) { return f.GetForUser(user); });
    }
    inline auto ToastNotificationManager::ConfigureNotificationMirroring(winrt::Windows::UI::Notifications::NotificationMirroring const& value)
    {
        impl::call_factory<ToastNotificationManager, IToastNotificationManagerStatics4>([&](IToastNotificationManagerStatics4 const& f) { return f.ConfigureNotificationMirroring(value); });
    }
    inline auto ToastNotificationManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser(*)(IToastNotificationManagerStatics5 const&), ToastNotificationManager, IToastNotificationManagerStatics5>([](IToastNotificationManagerStatics5 const& f) { return f.GetDefault(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Notifications::IAdaptiveNotificationContent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IAdaptiveNotificationText> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IBadgeNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IBadgeNotificationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IKnownNotificationBindingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::INotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::INotificationBinding> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::INotificationData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::INotificationDataFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::INotificationVisual> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledTileNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledTileNotificationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IShownTileNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutNotificationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileNotificationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdateManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdateManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdateManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdater2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastActivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastActivatedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastCollectionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastCollectionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastDismissedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotifier2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IToastNotifier3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IUserNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::AdaptiveNotificationText> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::BadgeNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::BadgeUpdateManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::BadgeUpdateManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::BadgeUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::KnownAdaptiveNotificationHints> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::KnownAdaptiveNotificationTextStyles> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::KnownNotificationBindings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::Notification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::NotificationBinding> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::NotificationData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::NotificationVisual> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ScheduledTileNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ScheduledToastNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ShownTileNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileFlyoutNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileFlyoutUpdateManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileFlyoutUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileUpdateManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileUpdateManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::TileUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastActivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastCollectionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastDismissedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationActionTriggerDetail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationHistory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationHistoryChangedTriggerDetail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::ToastNotifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::UserNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::UserNotificationChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
