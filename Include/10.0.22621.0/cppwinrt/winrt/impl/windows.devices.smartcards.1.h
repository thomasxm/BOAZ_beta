// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_SmartCards_1_H
#define WINRT_Windows_Devices_SmartCards_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.SmartCards.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::SmartCards
{
    struct __declspec(empty_bases) ICardAddedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICardAddedEventArgs>
    {
        ICardAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICardAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICardRemovedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICardRemovedEventArgs>
    {
        ICardRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICardRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKnownSmartCardAppletIds :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKnownSmartCardAppletIds>
    {
        IKnownSmartCardAppletIds(std::nullptr_t = nullptr) noexcept {}
        IKnownSmartCardAppletIds(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCard :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCard>
    {
        ISmartCard(std::nullptr_t = nullptr) noexcept {}
        ISmartCard(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAppletIdGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAppletIdGroup>
    {
        ISmartCardAppletIdGroup(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAppletIdGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAppletIdGroup2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAppletIdGroup2>
    {
        ISmartCardAppletIdGroup2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAppletIdGroup2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAppletIdGroupFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAppletIdGroupFactory>
    {
        ISmartCardAppletIdGroupFactory(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAppletIdGroupFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAppletIdGroupRegistration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAppletIdGroupRegistration>
    {
        ISmartCardAppletIdGroupRegistration(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAppletIdGroupRegistration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAppletIdGroupRegistration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAppletIdGroupRegistration2>
    {
        ISmartCardAppletIdGroupRegistration2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAppletIdGroupRegistration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAppletIdGroupStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAppletIdGroupStatics>
    {
        ISmartCardAppletIdGroupStatics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAppletIdGroupStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAutomaticResponseApdu :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAutomaticResponseApdu>
    {
        ISmartCardAutomaticResponseApdu(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAutomaticResponseApdu(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAutomaticResponseApdu2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAutomaticResponseApdu2>
    {
        ISmartCardAutomaticResponseApdu2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAutomaticResponseApdu2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAutomaticResponseApdu3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAutomaticResponseApdu3>
    {
        ISmartCardAutomaticResponseApdu3(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAutomaticResponseApdu3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardAutomaticResponseApduFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardAutomaticResponseApduFactory>
    {
        ISmartCardAutomaticResponseApduFactory(std::nullptr_t = nullptr) noexcept {}
        ISmartCardAutomaticResponseApduFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardChallengeContext :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardChallengeContext>,
        impl::require<winrt::Windows::Devices::SmartCards::ISmartCardChallengeContext, winrt::Windows::Foundation::IClosable>
    {
        ISmartCardChallengeContext(std::nullptr_t = nullptr) noexcept {}
        ISmartCardChallengeContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardConnect :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardConnect>
    {
        ISmartCardConnect(std::nullptr_t = nullptr) noexcept {}
        ISmartCardConnect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardConnection>,
        impl::require<winrt::Windows::Devices::SmartCards::ISmartCardConnection, winrt::Windows::Foundation::IClosable>
    {
        ISmartCardConnection(std::nullptr_t = nullptr) noexcept {}
        ISmartCardConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGenerator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGenerator>
    {
        ISmartCardCryptogramGenerator(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGenerator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGenerator2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGenerator2>
    {
        ISmartCardCryptogramGenerator2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGenerator2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGeneratorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGeneratorStatics>
    {
        ISmartCardCryptogramGeneratorStatics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGeneratorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGeneratorStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGeneratorStatics2>
    {
        ISmartCardCryptogramGeneratorStatics2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGeneratorStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult>
    {
        ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGetAllCryptogramMaterialCharacteristicsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult>
    {
        ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGetAllCryptogramMaterialPackageCharacteristicsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult>
    {
        ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramGetAllCryptogramStorageKeyCharacteristicsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramMaterialCharacteristics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramMaterialCharacteristics>
    {
        ISmartCardCryptogramMaterialCharacteristics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramMaterialCharacteristics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramMaterialPackageCharacteristics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramMaterialPackageCharacteristics>
    {
        ISmartCardCryptogramMaterialPackageCharacteristics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramMaterialPackageCharacteristics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramMaterialPossessionProof :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramMaterialPossessionProof>
    {
        ISmartCardCryptogramMaterialPossessionProof(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramMaterialPossessionProof(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramPlacementStep :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramPlacementStep>
    {
        ISmartCardCryptogramPlacementStep(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramPlacementStep(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramStorageKeyCharacteristics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramStorageKeyCharacteristics>
    {
        ISmartCardCryptogramStorageKeyCharacteristics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramStorageKeyCharacteristics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramStorageKeyInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramStorageKeyInfo>
    {
        ISmartCardCryptogramStorageKeyInfo(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramStorageKeyInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardCryptogramStorageKeyInfo2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardCryptogramStorageKeyInfo2>
    {
        ISmartCardCryptogramStorageKeyInfo2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardCryptogramStorageKeyInfo2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulator>
    {
        ISmartCardEmulator(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulator2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulator2>
    {
        ISmartCardEmulator2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulator2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorApduReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorApduReceivedEventArgs>
    {
        ISmartCardEmulatorApduReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorApduReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorApduReceivedEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorApduReceivedEventArgs2>
    {
        ISmartCardEmulatorApduReceivedEventArgs2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorApduReceivedEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorApduReceivedEventArgsWithCryptograms :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorApduReceivedEventArgsWithCryptograms>
    {
        ISmartCardEmulatorApduReceivedEventArgsWithCryptograms(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorApduReceivedEventArgsWithCryptograms(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorConnectionDeactivatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorConnectionDeactivatedEventArgs>
    {
        ISmartCardEmulatorConnectionDeactivatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorConnectionDeactivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorConnectionProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorConnectionProperties>
    {
        ISmartCardEmulatorConnectionProperties(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorConnectionProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorStatics>
    {
        ISmartCardEmulatorStatics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorStatics2>
    {
        ISmartCardEmulatorStatics2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardEmulatorStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardEmulatorStatics3>
    {
        ISmartCardEmulatorStatics3(std::nullptr_t = nullptr) noexcept {}
        ISmartCardEmulatorStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardPinPolicy :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardPinPolicy>
    {
        ISmartCardPinPolicy(std::nullptr_t = nullptr) noexcept {}
        ISmartCardPinPolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardPinResetDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardPinResetDeferral>
    {
        ISmartCardPinResetDeferral(std::nullptr_t = nullptr) noexcept {}
        ISmartCardPinResetDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardPinResetRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardPinResetRequest>
    {
        ISmartCardPinResetRequest(std::nullptr_t = nullptr) noexcept {}
        ISmartCardPinResetRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardProvisioning :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardProvisioning>
    {
        ISmartCardProvisioning(std::nullptr_t = nullptr) noexcept {}
        ISmartCardProvisioning(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardProvisioning2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardProvisioning2>
    {
        ISmartCardProvisioning2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardProvisioning2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardProvisioningStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardProvisioningStatics>
    {
        ISmartCardProvisioningStatics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardProvisioningStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardProvisioningStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardProvisioningStatics2>
    {
        ISmartCardProvisioningStatics2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardProvisioningStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardReader>
    {
        ISmartCardReader(std::nullptr_t = nullptr) noexcept {}
        ISmartCardReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardReaderStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardReaderStatics>
    {
        ISmartCardReaderStatics(std::nullptr_t = nullptr) noexcept {}
        ISmartCardReaderStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardTriggerDetails>
    {
        ISmartCardTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        ISmartCardTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardTriggerDetails2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardTriggerDetails2>
    {
        ISmartCardTriggerDetails2(std::nullptr_t = nullptr) noexcept {}
        ISmartCardTriggerDetails2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmartCardTriggerDetails3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmartCardTriggerDetails3>
    {
        ISmartCardTriggerDetails3(std::nullptr_t = nullptr) noexcept {}
        ISmartCardTriggerDetails3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
