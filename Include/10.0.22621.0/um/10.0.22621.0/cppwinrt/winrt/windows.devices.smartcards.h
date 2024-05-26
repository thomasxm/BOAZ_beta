// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_SmartCards_H
#define WINRT_Windows_Devices_SmartCards_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.SmartCards.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCard) consume_Windows_Devices_SmartCards_ICardAddedEventArgs<D>::SmartCard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ICardAddedEventArgs)->get_SmartCard(&value));
        return winrt::Windows::Devices::SmartCards::SmartCard{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCard) consume_Windows_Devices_SmartCards_ICardRemovedEventArgs<D>::SmartCard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ICardRemovedEventArgs)->get_SmartCard(&value));
        return winrt::Windows::Devices::SmartCards::SmartCard{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_IKnownSmartCardAppletIds<D>::PaymentSystemEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds)->get_PaymentSystemEnvironment(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_IKnownSmartCardAppletIds<D>::ProximityPaymentSystemEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds)->get_ProximityPaymentSystemEnvironment(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardReader) consume_Windows_Devices_SmartCards_ISmartCard<D>::Reader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCard)->get_Reader(&value));
        return winrt::Windows::Devices::SmartCards::SmartCardReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardStatus>) consume_Windows_Devices_SmartCards_ISmartCard<D>::GetStatusAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCard)->GetStatusAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_SmartCards_ISmartCard<D>::GetAnswerToResetAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCard)->GetAnswerToResetAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::AppletIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_AppletIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationCategory() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_SmartCardEmulationCategory(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationCategory(winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_SmartCardEmulationCategory(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulationType) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationType() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardEmulationType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_SmartCardEmulationType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::SmartCardEmulationType(winrt::Windows::Devices::SmartCards::SmartCardEmulationType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_SmartCardEmulationType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::AutomaticEnablement() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->get_AutomaticEnablement(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup<D>::AutomaticEnablement(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup)->put_AutomaticEnablement(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Logo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_Logo(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Logo(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->put_Logo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::SecureUserAuthenticationRequired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->get_SecureUserAuthenticationRequired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroup2<D>::SecureUserAuthenticationRequired(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2)->put_SecureUserAuthenticationRequired(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupFactory<D>::Create(param::hstring const& displayName, param::vector<winrt::Windows::Storage::Streams::IBuffer> const& appletIds, winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory const& emulationCategory, winrt::Windows::Devices::SmartCards::SmartCardEmulationType const& emulationType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory)->Create(*(void**)(&displayName), *(void**)(&appletIds), static_cast<int32_t>(emulationCategory), static_cast<int32_t>(emulationType), &result));
        return winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::ActivationPolicy() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->get_ActivationPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::AppletIdGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->get_AppletIdGroup(&value));
        return winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult>) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::RequestActivationPolicyChangeAsync(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy const& policy) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->RequestActivationPolicyChangeAsync(static_cast<int32_t>(policy), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::Id() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration<D>::SetAutomaticResponseApdusAsync(param::async_iterable<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> const& apdus) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration)->SetAutomaticResponseApdusAsync(*(void**)(&apdus), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration2<D>::SmartCardReaderId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2)->get_SmartCardReaderId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupRegistration2<D>::SetPropertiesAsync(winrt::Windows::Foundation::Collections::ValueSet const& props) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2)->SetPropertiesAsync(*(void**)(&props), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_SmartCards_ISmartCardAppletIdGroupStatics<D>::MaxAppletIds() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics)->get_MaxAppletIds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApdu() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_CommandApdu(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApdu(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_CommandApdu(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApduBitMask() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_CommandApduBitMask(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::CommandApduBitMask(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_CommandApduBitMask(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ShouldMatchLength() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_ShouldMatchLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ShouldMatchLength(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_ShouldMatchLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::AppletId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_AppletId(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::AppletId(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_AppletId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ResponseApdu() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->get_ResponseApdu(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu<D>::ResponseApdu(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu)->put_ResponseApdu(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::InputState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->get_InputState(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::InputState(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->put_InputState(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::OutputState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->get_OutputState(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu2<D>::OutputState(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2)->put_OutputState(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu3<D>::AllowWhenCryptogramGeneratorNotPrepared() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3)->get_AllowWhenCryptogramGeneratorNotPrepared(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApdu3<D>::AllowWhenCryptogramGeneratorNotPrepared(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3)->put_AllowWhenCryptogramGeneratorNotPrepared(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu) consume_Windows_Devices_SmartCards_ISmartCardAutomaticResponseApduFactory<D>::Create(winrt::Windows::Storage::Streams::IBuffer const& commandApdu, winrt::Windows::Storage::Streams::IBuffer const& responseApdu) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory)->Create(*(void**)(&commandApdu), *(void**)(&responseApdu), &result));
        return winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::Challenge() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext)->get_Challenge(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::VerifyResponseAsync(winrt::Windows::Storage::Streams::IBuffer const& response) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext)->VerifyResponseAsync(*(void**)(&response), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::ProvisionAsync(winrt::Windows::Storage::Streams::IBuffer const& response, bool formatCard) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext)->ProvisionAsync(*(void**)(&response), formatCard, &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::ProvisionAsync(winrt::Windows::Storage::Streams::IBuffer const& response, bool formatCard, winrt::guid const& newCardId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext)->ProvisionAsyncWithNewCardId(*(void**)(&response), formatCard, impl::bind_in(newCardId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_SmartCards_ISmartCardChallengeContext<D>::ChangeAdministrativeKeyAsync(winrt::Windows::Storage::Streams::IBuffer const& response, winrt::Windows::Storage::Streams::IBuffer const& newAdministrativeKey) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext)->ChangeAdministrativeKeyAsync(*(void**)(&response), *(void**)(&newAdministrativeKey), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardConnection>) consume_Windows_Devices_SmartCards_ISmartCardConnect<D>::ConnectAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardConnect)->ConnectAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardConnection>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_SmartCards_ISmartCardConnection<D>::TransmitAsync(winrt::Windows::Storage::Streams::IBuffer const& command) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardConnection)->TransmitAsync(*(void**)(&command), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramMaterialTypes() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramMaterialTypes(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramAlgorithms() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramAlgorithms(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramMaterialPackageFormats() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramMaterialPackageFormats(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedCryptogramMaterialPackageConfirmationResponseFormats() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedCryptogramMaterialPackageConfirmationResponseFormats(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::SupportedSmartCardCryptogramStorageKeyCapabilities() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->get_SupportedSmartCardCryptogramStorageKeyCapabilities(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::DeleteCryptogramMaterialStorageKeyAsync(param::hstring const& storageKeyName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->DeleteCryptogramMaterialStorageKeyAsync(*(void**)(&storageKeyName), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::CreateCryptogramMaterialStorageKeyAsync(winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, param::hstring const& storageKeyName, winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm const& algorithm, winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities const& capabilities) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->CreateCryptogramMaterialStorageKeyAsync(static_cast<int32_t>(promptingBehavior), *(void**)(&storageKeyName), static_cast<int32_t>(algorithm), static_cast<uint32_t>(capabilities), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::RequestCryptogramMaterialStorageKeyInfoAsync(winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, param::hstring const& storageKeyName, winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& format) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->RequestCryptogramMaterialStorageKeyInfoAsync(static_cast<int32_t>(promptingBehavior), *(void**)(&storageKeyName), static_cast<int32_t>(format), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::ImportCryptogramMaterialPackageAsync(winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat const& format, param::hstring const& storageKeyName, param::hstring const& materialPackageName, winrt::Windows::Storage::Streams::IBuffer const& cryptogramMaterialPackage) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->ImportCryptogramMaterialPackageAsync(static_cast<int32_t>(format), *(void**)(&storageKeyName), *(void**)(&materialPackageName), *(void**)(&cryptogramMaterialPackage), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::TryProvePossessionOfCryptogramMaterialPackageAsync(winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat const& responseFormat, param::hstring const& materialPackageName, param::hstring const& materialName, winrt::Windows::Storage::Streams::IBuffer const& challenge) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->TryProvePossessionOfCryptogramMaterialPackageAsync(static_cast<int32_t>(promptingBehavior), static_cast<int32_t>(responseFormat), *(void**)(&materialPackageName), *(void**)(&materialName), *(void**)(&challenge), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::RequestUnlockCryptogramMaterialForUseAsync(winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->RequestUnlockCryptogramMaterialForUseAsync(static_cast<int32_t>(promptingBehavior), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator<D>::DeleteCryptogramMaterialPackageAsync(param::hstring const& materialPackageName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator)->DeleteCryptogramMaterialPackageAsync(*(void**)(&materialPackageName), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::ValidateRequestApduAsync(winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, winrt::Windows::Storage::Streams::IBuffer const& apduToValidate, param::async_iterable<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const& cryptogramPlacementSteps) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->ValidateRequestApduAsync(static_cast<int32_t>(promptingBehavior), *(void**)(&apduToValidate), *(void**)(&cryptogramPlacementSteps), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramStorageKeyCharacteristicsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramStorageKeyCharacteristicsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramMaterialPackageCharacteristicsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramMaterialPackageCharacteristicsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramMaterialPackageCharacteristicsAsync(param::hstring const& storageKeyName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramMaterialPackageCharacteristicsWithStorageKeyAsync(*(void**)(&storageKeyName), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGenerator2<D>::GetAllCryptogramMaterialCharacteristicsAsync(winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const& promptingBehavior, param::hstring const& materialPackageName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2)->GetAllCryptogramMaterialCharacteristicsAsync(static_cast<int32_t>(promptingBehavior), *(void**)(&materialPackageName), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGeneratorStatics<D>::GetSmartCardCryptogramGeneratorAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics)->GetSmartCardCryptogramGeneratorAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGeneratorStatics2<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult<D>::OperationStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult)->get_OperationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult<D>::Characteristics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult)->get_Characteristics(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult<D>::OperationStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult)->get_OperationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult<D>::Characteristics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult)->get_Characteristics(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult<D>::OperationStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult)->get_OperationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult<D>::Characteristics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult)->get_Characteristics(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::MaterialName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_MaterialName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::AllowedAlgorithms() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_AllowedAlgorithms(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::AllowedProofOfPossessionAlgorithms() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_AllowedProofOfPossessionAlgorithms(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::AllowedValidations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_AllowedValidations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialType) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::MaterialType() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_MaterialType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::ProtectionMethod() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_ProtectionMethod(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::ProtectionVersion() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_ProtectionVersion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialCharacteristics<D>::MaterialLength() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics)->get_MaterialLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::PackageName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_PackageName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::StorageKeyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_StorageKeyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::DateImported() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_DateImported(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPackageCharacteristics<D>::PackageFormat() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics)->get_PackageFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPossessionProof<D>::OperationStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof)->get_OperationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardCryptogramMaterialPossessionProof<D>::Proof() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof)->get_Proof(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::Algorithm() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_Algorithm(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::Algorithm(winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_Algorithm(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::SourceData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_SourceData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::SourceData(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_SourceData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialPackageName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramMaterialPackageName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialPackageName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramMaterialPackageName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramMaterialName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramMaterialName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramMaterialName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::TemplateOffset() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_TemplateOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::TemplateOffset(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_TemplateOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramOffset() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramOffset(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramLength() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramLength(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramPlacementOptions() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_CryptogramPlacementOptions(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::CryptogramPlacementOptions(winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_CryptogramPlacementOptions(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::ChainedOutputStep() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->get_ChainedOutputStep(&value));
        return winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardCryptogramPlacementStep<D>::ChainedOutputStep(winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep)->put_ChainedOutputStep(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::StorageKeyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_StorageKeyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::DateCreated() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_DateCreated(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::Algorithm() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_Algorithm(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyCharacteristics<D>::Capabilities() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics)->get_Capabilities(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::OperationStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_OperationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::PublicKeyBlobType() const
    {
        winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_PublicKeyBlobType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::PublicKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_PublicKey(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::AttestationStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_AttestationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::Attestation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_Attestation(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::AttestationCertificateChain() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_AttestationCertificateChain(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo<D>::Capabilities() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo)->get_Capabilities(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardCryptogramStorageKeyInfo2<D>::OperationalRequirements() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2)->get_OperationalRequirements(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy) consume_Windows_Devices_SmartCards_ISmartCardEmulator<D>::EnablementPolicy() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator)->get_EnablementPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardEmulator, winrt::Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator2)->add_ApduReceived(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived_revoker consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardEmulator, winrt::Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, ApduReceived_revoker>(this, ApduReceived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ApduReceived(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator2)->remove_ApduReceived(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardEmulator, winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator2)->add_ConnectionDeactivated(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated_revoker consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardEmulator, winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, ConnectionDeactivated_revoker>(this, ConnectionDeactivated(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::ConnectionDeactivated(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator2)->remove_ConnectionDeactivated(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator2)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardEmulator2<D>::IsHostCardEmulationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulator2)->IsHostCardEmulationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::CommandApdu() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->get_CommandApdu(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::ConnectionProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->get_ConnectionProperties(&value));
        return winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::TryRespondAsync(winrt::Windows::Storage::Streams::IBuffer const& responseApdu) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->TryRespondAsync(*(void**)(&responseApdu), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs<D>::AutomaticResponseStatus() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs)->get_AutomaticResponseStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs2<D>::State() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2)->get_State(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgs2<D>::TryRespondAsync(winrt::Windows::Storage::Streams::IBuffer const& responseApdu, winrt::Windows::Foundation::IReference<uint32_t> const& nextState) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2)->TryRespondWithStateAsync(*(void**)(&responseApdu), *(void**)(&nextState), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgsWithCryptograms<D>::TryRespondWithCryptogramsAsync(winrt::Windows::Storage::Streams::IBuffer const& responseTemplate, param::async_iterable<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const& cryptogramPlacementSteps) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms)->TryRespondWithCryptogramsAsync(*(void**)(&responseTemplate), *(void**)(&cryptogramPlacementSteps), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorApduReceivedEventArgsWithCryptograms<D>::TryRespondWithCryptogramsAsync(winrt::Windows::Storage::Streams::IBuffer const& responseTemplate, param::async_iterable<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const& cryptogramPlacementSteps, winrt::Windows::Foundation::IReference<uint32_t> const& nextState) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms)->TryRespondWithCryptogramsAndStateAsync(*(void**)(&responseTemplate), *(void**)(&cryptogramPlacementSteps), *(void**)(&nextState), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties) consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionDeactivatedEventArgs<D>::ConnectionProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs)->get_ConnectionProperties(&value));
        return winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason) consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionDeactivatedEventArgs<D>::Reason() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionProperties<D>::Id() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource) consume_Windows_Devices_SmartCards_ISmartCardEmulatorConnectionProperties<D>::Source() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties)->get_Source(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardEmulator>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardEmulator>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::GetAppletIdGroupRegistrationsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->GetAppletIdGroupRegistrationsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>) consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::RegisterAppletIdGroupAsync(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup const& appletIdGroup) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->RegisterAppletIdGroupAsync(*(void**)(&appletIdGroup), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::UnregisterAppletIdGroupAsync(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const& registration) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->UnregisterAppletIdGroupAsync(*(void**)(&registration), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics2<D>::MaxAppletIdGroupRegistrations() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2)->get_MaxAppletIdGroupRegistrations(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_SmartCards_ISmartCardEmulatorStatics3<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics3)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MinLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_MinLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MinLength(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_MinLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MaxLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_MaxLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::MaxLength(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_MaxLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::UppercaseLetters() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_UppercaseLetters(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::UppercaseLetters(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_UppercaseLetters(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::LowercaseLetters() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_LowercaseLetters(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::LowercaseLetters(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_LowercaseLetters(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::Digits() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_Digits(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::Digits(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_Digits(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::SpecialCharacters() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->get_SpecialCharacters(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinPolicy<D>::SpecialCharacters(winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy)->put_SpecialCharacters(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinResetDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinResetDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::Challenge() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest)->get_Challenge(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::Deadline() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest)->get_Deadline(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardPinResetDeferral) consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest)->GetDeferral(&result));
        return winrt::Windows::Devices::SmartCards::SmartCardPinResetDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardPinResetRequest<D>::SetResponse(winrt::Windows::Storage::Streams::IBuffer const& response) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest)->SetResponse(*(void**)(&response)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCard) consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::SmartCard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning)->get_SmartCard(&value));
        return winrt::Windows::Devices::SmartCards::SmartCard{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::guid>) consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::GetIdAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning)->GetIdAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::guid>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::GetNameAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning)->GetNameAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardChallengeContext>) consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::GetChallengeContextAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning)->GetChallengeContextAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardChallengeContext>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::RequestPinChangeAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning)->RequestPinChangeAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardProvisioning<D>::RequestPinResetAsync(winrt::Windows::Devices::SmartCards::SmartCardPinResetHandler const& handler) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning)->RequestPinResetAsync(*(void**)(&handler), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_SmartCards_ISmartCardProvisioning2<D>::GetAuthorityKeyContainerNameAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioning2)->GetAuthorityKeyContainerNameAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>) consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::FromSmartCardAsync(winrt::Windows::Devices::SmartCards::SmartCard const& card) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->FromSmartCardAsync(*(void**)(&card), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>) consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->RequestVirtualSmartCardCreationAsync(*(void**)(&friendlyName), *(void**)(&administrativeKey), *(void**)(&pinPolicy), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>) consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->RequestVirtualSmartCardCreationAsyncWithCardId(*(void**)(&friendlyName), *(void**)(&administrativeKey), *(void**)(&pinPolicy), impl::bind_in(cardId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics<D>::RequestVirtualSmartCardDeletionAsync(winrt::Windows::Devices::SmartCards::SmartCard const& card) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics)->RequestVirtualSmartCardDeletionAsync(*(void**)(&card), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>) consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics2<D>::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2)->RequestAttestedVirtualSmartCardCreationAsync(*(void**)(&friendlyName), *(void**)(&administrativeKey), *(void**)(&pinPolicy), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>) consume_Windows_Devices_SmartCards_ISmartCardProvisioningStatics2<D>::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2)->RequestAttestedVirtualSmartCardCreationAsyncWithCardId(*(void**)(&friendlyName), *(void**)(&administrativeKey), *(void**)(&pinPolicy), impl::bind_in(cardId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardReaderKind) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::Kind() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardReaderKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardReaderStatus>) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::GetStatusAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->GetStatusAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardReaderStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCard>>) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::FindAllCardsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->FindAllCardsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCard>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardReader, winrt::Windows::Devices::SmartCards::CardAddedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->add_CardAdded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded_revoker consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardReader, winrt::Windows::Devices::SmartCards::CardAddedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CardAdded_revoker>(this, CardAdded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardAdded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->remove_CardAdded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardReader, winrt::Windows::Devices::SmartCards::CardRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->add_CardRemoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved_revoker consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardReader, winrt::Windows::Devices::SmartCards::CardRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CardRemoved_revoker>(this, CardRemoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_SmartCards_ISmartCardReader<D>::CardRemoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReader)->remove_CardRemoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardReaderStatics<D>::GetDeviceSelector() const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics)->GetDeviceSelector(&selector));
        return hstring{ selector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_SmartCards_ISmartCardReaderStatics<D>::GetDeviceSelector(winrt::Windows::Devices::SmartCards::SmartCardReaderKind const& kind) const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics)->GetDeviceSelectorWithKind(static_cast<int32_t>(kind), &selector));
        return hstring{ selector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardReader>) consume_Windows_Devices_SmartCards_ISmartCardReaderStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardReader>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardTriggerType) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails<D>::TriggerType() const
    {
        winrt::Windows::Devices::SmartCards::SmartCardTriggerType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails)->get_TriggerType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails<D>::SourceAppletId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails)->get_SourceAppletId(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails<D>::TriggerData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails)->get_TriggerData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCardEmulator) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails2<D>::Emulator() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2)->get_Emulator(&value));
        return winrt::Windows::Devices::SmartCards::SmartCardEmulator{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails2<D>::TryLaunchCurrentAppAsync(param::hstring const& arguments) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2)->TryLaunchCurrentAppAsync(*(void**)(&arguments), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails2<D>::TryLaunchCurrentAppAsync(param::hstring const& arguments, winrt::Windows::Devices::SmartCards::SmartCardLaunchBehavior const& behavior) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2)->TryLaunchCurrentAppWithBehaviorAsync(*(void**)(&arguments), static_cast<int32_t>(behavior), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::SmartCards::SmartCard) consume_Windows_Devices_SmartCards_ISmartCardTriggerDetails3<D>::SmartCard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails3)->get_SmartCard(&value));
        return winrt::Windows::Devices::SmartCards::SmartCard{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Devices::SmartCards::SmartCardPinResetHandler, H> final : implements_delegate<winrt::Windows::Devices::SmartCards::SmartCardPinResetHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Devices::SmartCards::SmartCardPinResetHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* request) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardProvisioning const*>(&sender), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinResetRequest const*>(&request));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ICardAddedEventArgs> : produce_base<D, winrt::Windows::Devices::SmartCards::ICardAddedEventArgs>
    {
        int32_t __stdcall get_SmartCard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ICardRemovedEventArgs> : produce_base<D, winrt::Windows::Devices::SmartCards::ICardRemovedEventArgs>
    {
        int32_t __stdcall get_SmartCard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds> : produce_base<D, winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds>
    {
        int32_t __stdcall get_PaymentSystemEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().PaymentSystemEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProximityPaymentSystemEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ProximityPaymentSystemEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCard> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCard>
    {
        int32_t __stdcall get_Reader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardReader>(this->shim().Reader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStatusAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardStatus>>(this->shim().GetStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnswerToResetAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().GetAnswerToResetAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup>
    {
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
        int32_t __stdcall get_AppletIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().AppletIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmartCardEmulationCategory(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory>(this->shim().SmartCardEmulationCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SmartCardEmulationCategory(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SmartCardEmulationCategory(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmartCardEmulationType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulationType>(this->shim().SmartCardEmulationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SmartCardEmulationType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SmartCardEmulationType(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardEmulationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutomaticEnablement(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutomaticEnablement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutomaticEnablement(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutomaticEnablement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2>
    {
        int32_t __stdcall get_Logo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Logo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Logo(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SecureUserAuthenticationRequired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SecureUserAuthenticationRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SecureUserAuthenticationRequired(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SecureUserAuthenticationRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory>
    {
        int32_t __stdcall Create(void* displayName, void* appletIds, int32_t emulationCategory, int32_t emulationType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup>(this->shim().Create(*reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer> const*>(&appletIds), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory const*>(&emulationCategory), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardEmulationType const*>(&emulationType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration>
    {
        int32_t __stdcall get_ActivationPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy>(this->shim().ActivationPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppletIdGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup>(this->shim().AppletIdGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestActivationPolicyChangeAsync(int32_t policy, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardActivationPolicyChangeResult>>(this->shim().RequestActivationPolicyChangeAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupActivationPolicy const*>(&policy)));
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
        int32_t __stdcall SetAutomaticResponseApdusAsync(void* apdus, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetAutomaticResponseApdusAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> const*>(&apdus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2>
    {
        int32_t __stdcall get_SmartCardReaderId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SmartCardReaderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertiesAsync(void* props, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetPropertiesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics>
    {
        int32_t __stdcall get_MaxAppletIds(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().MaxAppletIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu>
    {
        int32_t __stdcall get_CommandApdu(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().CommandApdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommandApdu(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandApdu(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommandApduBitMask(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().CommandApduBitMask());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommandApduBitMask(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandApduBitMask(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldMatchLength(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldMatchLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldMatchLength(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldMatchLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppletId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().AppletId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppletId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppletId(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseApdu(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ResponseApdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ResponseApdu(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResponseApdu(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2>
    {
        int32_t __stdcall get_InputState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().InputState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InputState(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InputState(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().OutputState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutputState(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutputState(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3>
    {
        int32_t __stdcall get_AllowWhenCryptogramGeneratorNotPrepared(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWhenCryptogramGeneratorNotPrepared());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWhenCryptogramGeneratorNotPrepared(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWhenCryptogramGeneratorNotPrepared(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory>
    {
        int32_t __stdcall Create(void* commandApdu, void* responseApdu, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu>(this->shim().Create(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&commandApdu), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&responseApdu)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext>
    {
        int32_t __stdcall get_Challenge(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Challenge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall VerifyResponseAsync(void* response, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().VerifyResponseAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&response)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProvisionAsync(void* response, bool formatCard, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ProvisionAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&response), formatCard));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProvisionAsyncWithNewCardId(void* response, bool formatCard, winrt::guid newCardId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ProvisionAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&response), formatCard, *reinterpret_cast<winrt::guid const*>(&newCardId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangeAdministrativeKeyAsync(void* response, void* newAdministrativeKey, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ChangeAdministrativeKeyAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&response), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&newAdministrativeKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardConnect> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardConnect>
    {
        int32_t __stdcall ConnectAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardConnection>>(this->shim().ConnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardConnection> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardConnection>
    {
        int32_t __stdcall TransmitAsync(void* command, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().TransmitAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&command)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator>
    {
        int32_t __stdcall get_SupportedCryptogramMaterialTypes(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>>(this->shim().SupportedCryptogramMaterialTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCryptogramAlgorithms(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>>(this->shim().SupportedCryptogramAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCryptogramMaterialPackageFormats(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>>(this->shim().SupportedCryptogramMaterialPackageFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCryptogramMaterialPackageConfirmationResponseFormats(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>>(this->shim().SupportedCryptogramMaterialPackageConfirmationResponseFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedSmartCardCryptogramStorageKeyCapabilities(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>>(this->shim().SupportedSmartCardCryptogramStorageKeyCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteCryptogramMaterialStorageKeyAsync(void* storageKeyName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().DeleteCryptogramMaterialStorageKeyAsync(*reinterpret_cast<hstring const*>(&storageKeyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCryptogramMaterialStorageKeyAsync(int32_t promptingBehavior, void* storageKeyName, int32_t algorithm, uint32_t capabilities, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().CreateCryptogramMaterialStorageKeyAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<hstring const*>(&storageKeyName), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm const*>(&algorithm), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities const*>(&capabilities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestCryptogramMaterialStorageKeyInfoAsync(int32_t promptingBehavior, void* storageKeyName, int32_t format, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo>>(this->shim().RequestCryptogramMaterialStorageKeyInfoAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<hstring const*>(&storageKeyName), *reinterpret_cast<winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ImportCryptogramMaterialPackageAsync(int32_t format, void* storageKeyName, void* materialPackageName, void* cryptogramMaterialPackage, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().ImportCryptogramMaterialPackageAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat const*>(&format), *reinterpret_cast<hstring const*>(&storageKeyName), *reinterpret_cast<hstring const*>(&materialPackageName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&cryptogramMaterialPackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryProvePossessionOfCryptogramMaterialPackageAsync(int32_t promptingBehavior, int32_t responseFormat, void* materialPackageName, void* materialName, void* challenge, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof>>(this->shim().TryProvePossessionOfCryptogramMaterialPackageAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat const*>(&responseFormat), *reinterpret_cast<hstring const*>(&materialPackageName), *reinterpret_cast<hstring const*>(&materialName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&challenge)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestUnlockCryptogramMaterialForUseAsync(int32_t promptingBehavior, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().RequestUnlockCryptogramMaterialForUseAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteCryptogramMaterialPackageAsync(void* materialPackageName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().DeleteCryptogramMaterialPackageAsync(*reinterpret_cast<hstring const*>(&materialPackageName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2>
    {
        int32_t __stdcall ValidateRequestApduAsync(int32_t promptingBehavior, void* apduToValidate, void* cryptogramPlacementSteps, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().ValidateRequestApduAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&apduToValidate), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const*>(&cryptogramPlacementSteps)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAllCryptogramStorageKeyCharacteristicsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>>(this->shim().GetAllCryptogramStorageKeyCharacteristicsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAllCryptogramMaterialPackageCharacteristicsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>>(this->shim().GetAllCryptogramMaterialPackageCharacteristicsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAllCryptogramMaterialPackageCharacteristicsWithStorageKeyAsync(void* storageKeyName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>>(this->shim().GetAllCryptogramMaterialPackageCharacteristicsAsync(*reinterpret_cast<hstring const*>(&storageKeyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAllCryptogramMaterialCharacteristicsAsync(int32_t promptingBehavior, void* materialPackageName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>>(this->shim().GetAllCryptogramMaterialCharacteristicsAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardUnlockPromptingBehavior const*>(&promptingBehavior), *reinterpret_cast<hstring const*>(&materialPackageName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics>
    {
        int32_t __stdcall GetSmartCardCryptogramGeneratorAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator>>(this->shim().GetSmartCardCryptogramGeneratorAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2>
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
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>
    {
        int32_t __stdcall get_OperationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Characteristics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>
    {
        int32_t __stdcall get_OperationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Characteristics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>
    {
        int32_t __stdcall get_OperationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Characteristics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics>
    {
        int32_t __stdcall get_MaterialName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MaterialName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedAlgorithms(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>>(this->shim().AllowedAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedProofOfPossessionAlgorithms(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageConfirmationResponseFormat>>(this->shim().AllowedProofOfPossessionAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedValidations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>>(this->shim().AllowedValidations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaterialType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialType>(this->shim().MaterialType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProtectionMethod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialProtectionMethod>(this->shim().ProtectionMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProtectionVersion(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProtectionVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaterialLength(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaterialLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics>
    {
        int32_t __stdcall get_PackageName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StorageKeyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StorageKeyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DateImported(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().DateImported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PackageFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageFormat>(this->shim().PackageFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof>
    {
        int32_t __stdcall get_OperationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Proof(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Proof());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep>
    {
        int32_t __stdcall get_Algorithm(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm>(this->shim().Algorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Algorithm(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Algorithm(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().SourceData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourceData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceData(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CryptogramMaterialPackageName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CryptogramMaterialPackageName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CryptogramMaterialPackageName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CryptogramMaterialPackageName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CryptogramMaterialName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CryptogramMaterialName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CryptogramMaterialName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CryptogramMaterialName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TemplateOffset(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().TemplateOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TemplateOffset(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TemplateOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CryptogramOffset(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CryptogramOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CryptogramOffset(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CryptogramOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CryptogramLength(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CryptogramLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CryptogramLength(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CryptogramLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CryptogramPlacementOptions(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions>(this->shim().CryptogramPlacementOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CryptogramPlacementOptions(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CryptogramPlacementOptions(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChainedOutputStep(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep>(this->shim().ChainedOutputStep());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChainedOutputStep(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChainedOutputStep(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics>
    {
        int32_t __stdcall get_StorageKeyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StorageKeyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DateCreated(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().DateCreated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Algorithm(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyAlgorithm>(this->shim().Algorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo>
    {
        int32_t __stdcall get_OperationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>(this->shim().OperationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicKeyBlobType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType>(this->shim().PublicKeyBlobType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicKey(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().PublicKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttestationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptographicKeyAttestationStatus>(this->shim().AttestationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Attestation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Attestation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttestationCertificateChain(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().AttestationCertificateChain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2>
    {
        int32_t __stdcall get_OperationalRequirements(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OperationalRequirements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulator> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulator>
    {
        int32_t __stdcall get_EnablementPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulatorEnablementPolicy>(this->shim().EnablementPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulator2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulator2>
    {
        int32_t __stdcall add_ApduReceived(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ApduReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardEmulator, winrt::Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ApduReceived(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApduReceived(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall add_ConnectionDeactivated(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionDeactivated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardEmulator, winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionDeactivated(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionDeactivated(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsHostCardEmulationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHostCardEmulationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs>
    {
        int32_t __stdcall get_CommandApdu(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().CommandApdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties>(this->shim().ConnectionProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRespondAsync(void* responseApdu, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRespondAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&responseApdu)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutomaticResponseStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseStatus>(this->shim().AutomaticResponseStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2>
    {
        int32_t __stdcall get_State(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRespondWithStateAsync(void* responseApdu, void* nextState, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRespondAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&responseApdu), *reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&nextState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms>
    {
        int32_t __stdcall TryRespondWithCryptogramsAsync(void* responseTemplate, void* cryptogramPlacementSteps, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().TryRespondWithCryptogramsAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&responseTemplate), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const*>(&cryptogramPlacementSteps)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRespondWithCryptogramsAndStateAsync(void* responseTemplate, void* cryptogramPlacementSteps, void* nextState, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGeneratorOperationStatus>>(this->shim().TryRespondWithCryptogramsAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&responseTemplate), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> const*>(&cryptogramPlacementSteps), *reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&nextState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs>
    {
        int32_t __stdcall get_ConnectionProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties>(this->shim().ConnectionProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties>
    {
        int32_t __stdcall get_Id(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardEmulator>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2>
    {
        int32_t __stdcall GetAppletIdGroupRegistrationsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>>(this->shim().GetAppletIdGroupRegistrationsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAppletIdGroupAsync(void* appletIdGroup, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>(this->shim().RegisterAppletIdGroupAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup const*>(&appletIdGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterAppletIdGroupAsync(void* registration, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UnregisterAppletIdGroupAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const*>(&registration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAppletIdGroupRegistrations(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().MaxAppletIdGroupRegistrations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics3> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics3>
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
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy>
    {
        int32_t __stdcall get_MinLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinLength(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxLength(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UppercaseLetters(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().UppercaseLetters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UppercaseLetters(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UppercaseLetters(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LowercaseLetters(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().LowercaseLetters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LowercaseLetters(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LowercaseLetters(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Digits(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().Digits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Digits(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Digits(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpecialCharacters(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption>(this->shim().SpecialCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpecialCharacters(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpecialCharacters(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinCharacterPolicyOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardPinResetDeferral> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardPinResetDeferral>
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
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest>
    {
        int32_t __stdcall get_Challenge(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Challenge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Deadline(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::SmartCards::SmartCardPinResetDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetResponse(void* response) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetResponse(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&response));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioning> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioning>
    {
        int32_t __stdcall get_SmartCard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIdAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::guid>>(this->shim().GetIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNameAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChallengeContextAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardChallengeContext>>(this->shim().GetChallengeContextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinChangeAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinChangeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinResetAsync(void* handler, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinResetAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinResetHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioning2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioning2>
    {
        int32_t __stdcall GetAuthorityKeyContainerNameAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAuthorityKeyContainerNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics>
    {
        int32_t __stdcall FromSmartCardAsync(void* card, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().FromSmartCardAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCard const*>(&card)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestVirtualSmartCardCreationAsync(void* friendlyName, void* administrativeKey, void* pinPolicy, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestVirtualSmartCardCreationAsyncWithCardId(void* friendlyName, void* administrativeKey, void* pinPolicy, winrt::guid cardId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy), *reinterpret_cast<winrt::guid const*>(&cardId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestVirtualSmartCardDeletionAsync(void* card, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestVirtualSmartCardDeletionAsync(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCard const*>(&card)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2>
    {
        int32_t __stdcall RequestAttestedVirtualSmartCardCreationAsync(void* friendlyName, void* administrativeKey, void* pinPolicy, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestAttestedVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAttestedVirtualSmartCardCreationAsyncWithCardId(void* friendlyName, void* administrativeKey, void* pinPolicy, winrt::guid cardId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardProvisioning>>(this->shim().RequestAttestedVirtualSmartCardCreationAsync(*reinterpret_cast<hstring const*>(&friendlyName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&administrativeKey), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const*>(&pinPolicy), *reinterpret_cast<winrt::guid const*>(&cardId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardReader> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardReader>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
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
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardReaderKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStatusAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardReaderStatus>>(this->shim().GetStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllCardsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCard>>>(this->shim().FindAllCardsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CardAdded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CardAdded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardReader, winrt::Windows::Devices::SmartCards::CardAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CardAdded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CardAdded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CardRemoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CardRemoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SmartCards::SmartCardReader, winrt::Windows::Devices::SmartCards::CardRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CardRemoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CardRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorWithKind(int32_t kind, void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardReaderKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardReader>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails>
    {
        int32_t __stdcall get_TriggerType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardTriggerType>(this->shim().TriggerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceAppletId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().SourceAppletId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TriggerData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().TriggerData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2>
    {
        int32_t __stdcall get_Emulator(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCardEmulator>(this->shim().Emulator());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryLaunchCurrentAppAsync(void* arguments, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryLaunchCurrentAppAsync(*reinterpret_cast<hstring const*>(&arguments)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryLaunchCurrentAppWithBehaviorAsync(void* arguments, int32_t behavior, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryLaunchCurrentAppAsync(*reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<winrt::Windows::Devices::SmartCards::SmartCardLaunchBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails3> : produce_base<D, winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails3>
    {
        int32_t __stdcall get_SmartCard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::SmartCards::SmartCard>(this->shim().SmartCard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::SmartCards
{
    constexpr auto operator|(SmartCardCryptogramPlacementOptions const left, SmartCardCryptogramPlacementOptions const right) noexcept
    {
        return static_cast<SmartCardCryptogramPlacementOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(SmartCardCryptogramPlacementOptions& left, SmartCardCryptogramPlacementOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(SmartCardCryptogramPlacementOptions const left, SmartCardCryptogramPlacementOptions const right) noexcept
    {
        return static_cast<SmartCardCryptogramPlacementOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(SmartCardCryptogramPlacementOptions& left, SmartCardCryptogramPlacementOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(SmartCardCryptogramPlacementOptions const value) noexcept
    {
        return static_cast<SmartCardCryptogramPlacementOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(SmartCardCryptogramPlacementOptions const left, SmartCardCryptogramPlacementOptions const right) noexcept
    {
        return static_cast<SmartCardCryptogramPlacementOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(SmartCardCryptogramPlacementOptions& left, SmartCardCryptogramPlacementOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(SmartCardCryptogramStorageKeyCapabilities const left, SmartCardCryptogramStorageKeyCapabilities const right) noexcept
    {
        return static_cast<SmartCardCryptogramStorageKeyCapabilities>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(SmartCardCryptogramStorageKeyCapabilities& left, SmartCardCryptogramStorageKeyCapabilities const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(SmartCardCryptogramStorageKeyCapabilities const left, SmartCardCryptogramStorageKeyCapabilities const right) noexcept
    {
        return static_cast<SmartCardCryptogramStorageKeyCapabilities>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(SmartCardCryptogramStorageKeyCapabilities& left, SmartCardCryptogramStorageKeyCapabilities const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(SmartCardCryptogramStorageKeyCapabilities const value) noexcept
    {
        return static_cast<SmartCardCryptogramStorageKeyCapabilities>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(SmartCardCryptogramStorageKeyCapabilities const left, SmartCardCryptogramStorageKeyCapabilities const right) noexcept
    {
        return static_cast<SmartCardCryptogramStorageKeyCapabilities>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(SmartCardCryptogramStorageKeyCapabilities& left, SmartCardCryptogramStorageKeyCapabilities const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto KnownSmartCardAppletIds::PaymentSystemEnvironment()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::Streams::IBuffer(*)(IKnownSmartCardAppletIds const&), KnownSmartCardAppletIds, IKnownSmartCardAppletIds>([](IKnownSmartCardAppletIds const& f) { return f.PaymentSystemEnvironment(); });
    }
    inline auto KnownSmartCardAppletIds::ProximityPaymentSystemEnvironment()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::Streams::IBuffer(*)(IKnownSmartCardAppletIds const&), KnownSmartCardAppletIds, IKnownSmartCardAppletIds>([](IKnownSmartCardAppletIds const& f) { return f.ProximityPaymentSystemEnvironment(); });
    }
    inline SmartCardAppletIdGroup::SmartCardAppletIdGroup() :
        SmartCardAppletIdGroup(impl::call_factory_cast<SmartCardAppletIdGroup(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardAppletIdGroup>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardAppletIdGroup>(); }))
    {
    }
    inline SmartCardAppletIdGroup::SmartCardAppletIdGroup(param::hstring const& displayName, param::vector<winrt::Windows::Storage::Streams::IBuffer> const& appletIds, winrt::Windows::Devices::SmartCards::SmartCardEmulationCategory const& emulationCategory, winrt::Windows::Devices::SmartCards::SmartCardEmulationType const& emulationType) :
        SmartCardAppletIdGroup(impl::call_factory<SmartCardAppletIdGroup, ISmartCardAppletIdGroupFactory>([&](ISmartCardAppletIdGroupFactory const& f) { return f.Create(displayName, appletIds, emulationCategory, emulationType); }))
    {
    }
    inline auto SmartCardAppletIdGroup::MaxAppletIds()
    {
        return impl::call_factory_cast<uint16_t(*)(ISmartCardAppletIdGroupStatics const&), SmartCardAppletIdGroup, ISmartCardAppletIdGroupStatics>([](ISmartCardAppletIdGroupStatics const& f) { return f.MaxAppletIds(); });
    }
    inline SmartCardAutomaticResponseApdu::SmartCardAutomaticResponseApdu(winrt::Windows::Storage::Streams::IBuffer const& commandApdu, winrt::Windows::Storage::Streams::IBuffer const& responseApdu) :
        SmartCardAutomaticResponseApdu(impl::call_factory<SmartCardAutomaticResponseApdu, ISmartCardAutomaticResponseApduFactory>([&](ISmartCardAutomaticResponseApduFactory const& f) { return f.Create(commandApdu, responseApdu); }))
    {
    }
    inline auto SmartCardCryptogramGenerator::GetSmartCardCryptogramGeneratorAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator>(*)(ISmartCardCryptogramGeneratorStatics const&), SmartCardCryptogramGenerator, ISmartCardCryptogramGeneratorStatics>([](ISmartCardCryptogramGeneratorStatics const& f) { return f.GetSmartCardCryptogramGeneratorAsync(); });
    }
    inline auto SmartCardCryptogramGenerator::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(ISmartCardCryptogramGeneratorStatics2 const&), SmartCardCryptogramGenerator, ISmartCardCryptogramGeneratorStatics2>([](ISmartCardCryptogramGeneratorStatics2 const& f) { return f.IsSupported(); });
    }
    inline SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult() :
        SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult(impl::call_factory_cast<SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>(); }))
    {
    }
    inline SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult() :
        SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult(impl::call_factory_cast<SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>(); }))
    {
    }
    inline SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult() :
        SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult(impl::call_factory_cast<SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>(); }))
    {
    }
    inline SmartCardCryptogramMaterialCharacteristics::SmartCardCryptogramMaterialCharacteristics() :
        SmartCardCryptogramMaterialCharacteristics(impl::call_factory_cast<SmartCardCryptogramMaterialCharacteristics(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramMaterialCharacteristics>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramMaterialCharacteristics>(); }))
    {
    }
    inline SmartCardCryptogramMaterialPackageCharacteristics::SmartCardCryptogramMaterialPackageCharacteristics() :
        SmartCardCryptogramMaterialPackageCharacteristics(impl::call_factory_cast<SmartCardCryptogramMaterialPackageCharacteristics(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramMaterialPackageCharacteristics>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramMaterialPackageCharacteristics>(); }))
    {
    }
    inline SmartCardCryptogramPlacementStep::SmartCardCryptogramPlacementStep() :
        SmartCardCryptogramPlacementStep(impl::call_factory_cast<SmartCardCryptogramPlacementStep(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramPlacementStep>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramPlacementStep>(); }))
    {
    }
    inline SmartCardCryptogramStorageKeyCharacteristics::SmartCardCryptogramStorageKeyCharacteristics() :
        SmartCardCryptogramStorageKeyCharacteristics(impl::call_factory_cast<SmartCardCryptogramStorageKeyCharacteristics(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardCryptogramStorageKeyCharacteristics>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardCryptogramStorageKeyCharacteristics>(); }))
    {
    }
    inline auto SmartCardEmulator::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SmartCards::SmartCardEmulator>(*)(ISmartCardEmulatorStatics const&), SmartCardEmulator, ISmartCardEmulatorStatics>([](ISmartCardEmulatorStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto SmartCardEmulator::GetAppletIdGroupRegistrationsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration>>(*)(ISmartCardEmulatorStatics2 const&), SmartCardEmulator, ISmartCardEmulatorStatics2>([](ISmartCardEmulatorStatics2 const& f) { return f.GetAppletIdGroupRegistrationsAsync(); });
    }
    inline auto SmartCardEmulator::RegisterAppletIdGroupAsync(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup const& appletIdGroup)
    {
        return impl::call_factory<SmartCardEmulator, ISmartCardEmulatorStatics2>([&](ISmartCardEmulatorStatics2 const& f) { return f.RegisterAppletIdGroupAsync(appletIdGroup); });
    }
    inline auto SmartCardEmulator::UnregisterAppletIdGroupAsync(winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration const& registration)
    {
        return impl::call_factory<SmartCardEmulator, ISmartCardEmulatorStatics2>([&](ISmartCardEmulatorStatics2 const& f) { return f.UnregisterAppletIdGroupAsync(registration); });
    }
    inline auto SmartCardEmulator::MaxAppletIdGroupRegistrations()
    {
        return impl::call_factory_cast<uint16_t(*)(ISmartCardEmulatorStatics2 const&), SmartCardEmulator, ISmartCardEmulatorStatics2>([](ISmartCardEmulatorStatics2 const& f) { return f.MaxAppletIdGroupRegistrations(); });
    }
    inline auto SmartCardEmulator::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(ISmartCardEmulatorStatics3 const&), SmartCardEmulator, ISmartCardEmulatorStatics3>([](ISmartCardEmulatorStatics3 const& f) { return f.IsSupported(); });
    }
    inline SmartCardPinPolicy::SmartCardPinPolicy() :
        SmartCardPinPolicy(impl::call_factory_cast<SmartCardPinPolicy(*)(winrt::Windows::Foundation::IActivationFactory const&), SmartCardPinPolicy>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SmartCardPinPolicy>(); }))
    {
    }
    inline auto SmartCardProvisioning::FromSmartCardAsync(winrt::Windows::Devices::SmartCards::SmartCard const& card)
    {
        return impl::call_factory<SmartCardProvisioning, ISmartCardProvisioningStatics>([&](ISmartCardProvisioningStatics const& f) { return f.FromSmartCardAsync(card); });
    }
    inline auto SmartCardProvisioning::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy)
    {
        return impl::call_factory<SmartCardProvisioning, ISmartCardProvisioningStatics>([&](ISmartCardProvisioningStatics const& f) { return f.RequestVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy); });
    }
    inline auto SmartCardProvisioning::RequestVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId)
    {
        return impl::call_factory<SmartCardProvisioning, ISmartCardProvisioningStatics>([&](ISmartCardProvisioningStatics const& f) { return f.RequestVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy, cardId); });
    }
    inline auto SmartCardProvisioning::RequestVirtualSmartCardDeletionAsync(winrt::Windows::Devices::SmartCards::SmartCard const& card)
    {
        return impl::call_factory<SmartCardProvisioning, ISmartCardProvisioningStatics>([&](ISmartCardProvisioningStatics const& f) { return f.RequestVirtualSmartCardDeletionAsync(card); });
    }
    inline auto SmartCardProvisioning::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy)
    {
        return impl::call_factory<SmartCardProvisioning, ISmartCardProvisioningStatics2>([&](ISmartCardProvisioningStatics2 const& f) { return f.RequestAttestedVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy); });
    }
    inline auto SmartCardProvisioning::RequestAttestedVirtualSmartCardCreationAsync(param::hstring const& friendlyName, winrt::Windows::Storage::Streams::IBuffer const& administrativeKey, winrt::Windows::Devices::SmartCards::SmartCardPinPolicy const& pinPolicy, winrt::guid const& cardId)
    {
        return impl::call_factory<SmartCardProvisioning, ISmartCardProvisioningStatics2>([&](ISmartCardProvisioningStatics2 const& f) { return f.RequestAttestedVirtualSmartCardCreationAsync(friendlyName, administrativeKey, pinPolicy, cardId); });
    }
    inline auto SmartCardReader::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ISmartCardReaderStatics const&), SmartCardReader, ISmartCardReaderStatics>([](ISmartCardReaderStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto SmartCardReader::GetDeviceSelector(winrt::Windows::Devices::SmartCards::SmartCardReaderKind const& kind)
    {
        return impl::call_factory<SmartCardReader, ISmartCardReaderStatics>([&](ISmartCardReaderStatics const& f) { return f.GetDeviceSelector(kind); });
    }
    inline auto SmartCardReader::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<SmartCardReader, ISmartCardReaderStatics>([&](ISmartCardReaderStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    template <typename L> SmartCardPinResetHandler::SmartCardPinResetHandler(L handler) :
        SmartCardPinResetHandler(impl::make_delegate<SmartCardPinResetHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> SmartCardPinResetHandler::SmartCardPinResetHandler(F* handler) :
        SmartCardPinResetHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> SmartCardPinResetHandler::SmartCardPinResetHandler(O* object, M method) :
        SmartCardPinResetHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> SmartCardPinResetHandler::SmartCardPinResetHandler(com_ptr<O>&& object, M method) :
        SmartCardPinResetHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> SmartCardPinResetHandler::SmartCardPinResetHandler(weak_ref<O>&& object, M method) :
        SmartCardPinResetHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto SmartCardPinResetHandler::operator()(winrt::Windows::Devices::SmartCards::SmartCardProvisioning const& sender, winrt::Windows::Devices::SmartCards::SmartCardPinResetRequest const& request) const
    {
        check_hresult((*(impl::abi_t<SmartCardPinResetHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&request)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::SmartCards::ICardAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ICardRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::IKnownSmartCardAppletIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroup2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupRegistration2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAppletIdGroupStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApdu3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardAutomaticResponseApduFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardConnect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGenerator2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGeneratorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialCharacteristics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPackageCharacteristics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramMaterialPossessionProof> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramPlacementStep> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyCharacteristics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardCryptogramStorageKeyInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulator2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorApduReceivedEventArgsWithCryptograms> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionDeactivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorConnectionProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardEmulatorStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardPinPolicy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardPinResetDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardPinResetRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioning> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioning2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardProvisioningStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardReaderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::ISmartCardTriggerDetails3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::CardAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::CardRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::KnownSmartCardAppletIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardAppletIdGroupRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardAutomaticResponseApdu> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardChallengeContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGenerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialCharacteristics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPackageCharacteristics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramMaterialPossessionProof> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramPlacementStep> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyCharacteristics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardCryptogramStorageKeyInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulatorApduReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionDeactivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardEmulatorConnectionProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardPinPolicy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardPinResetDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardPinResetRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardProvisioning> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::SmartCards::SmartCardTriggerDetails> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
