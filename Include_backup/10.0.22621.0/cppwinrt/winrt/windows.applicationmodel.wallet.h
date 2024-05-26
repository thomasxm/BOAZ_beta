// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Wallet_H
#define WINRT_Windows_ApplicationModel_Wallet_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.Wallet.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology) consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>::Symbology() const
    {
        winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletBarcode)->get_Symbology(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletBarcode)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>) consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>::GetImageAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletBarcode)->GetImageAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcode) consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory<D>::CreateWalletBarcode(winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const& symbology, param::hstring const& value) const
    {
        void* barcode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory)->CreateWalletBarcode(static_cast<int32_t>(symbology), *(void**)(&value), &barcode));
        return winrt::Windows::ApplicationModel::Wallet::WalletBarcode{ barcode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcode) consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory<D>::CreateCustomWalletBarcode(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& streamToBarcodeImage) const
    {
        void* barcode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory)->CreateCustomWalletBarcode(*(void**)(&streamToBarcodeImage), &barcode));
        return winrt::Windows::ApplicationModel::Wallet::WalletBarcode{ barcode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsAcknowledged() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_IsAcknowledged(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsAcknowledged(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_IsAcknowledged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IssuerDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_IssuerDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IssuerDisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_IssuerDisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LastUpdated() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_LastUpdated(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LastUpdated(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_LastUpdated(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletItemKind) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Wallet::WalletItemKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcode) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Barcode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Barcode(&value));
        return winrt::Windows::ApplicationModel::Wallet::WalletBarcode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Barcode(winrt::Windows::ApplicationModel::Wallet::WalletBarcode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_Barcode(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::ExpirationDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_ExpirationDate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::ExpirationDate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_ExpirationDate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo159x159() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Logo159x159(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo159x159(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_Logo159x159(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo336x336() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Logo336x336(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo336x336(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_Logo336x336(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo99x99() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Logo99x99(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Logo99x99(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_Logo99x99(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_DisplayMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_DisplayMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsDisplayMessageLaunchable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_IsDisplayMessageLaunchable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsDisplayMessageLaunchable(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_IsDisplayMessageLaunchable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_LogoText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_LogoText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_HeaderColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_HeaderColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_BodyColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_BodyColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderFontColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_HeaderFontColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderFontColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_HeaderFontColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyFontColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_BodyFontColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyFontColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_BodyFontColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderBackgroundImage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_HeaderBackgroundImage(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::HeaderBackgroundImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_HeaderBackgroundImage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyBackgroundImage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_BodyBackgroundImage(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::BodyBackgroundImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_BodyBackgroundImage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoImage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_LogoImage(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::LogoImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_LogoImage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::PromotionalImage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_PromotionalImage(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::PromotionalImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_PromotionalImage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_RelevantDate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_RelevantDate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDateDisplayMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_RelevantDateDisplayMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantDateDisplayMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_RelevantDateDisplayMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletTransaction>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::TransactionHistory() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_TransactionHistory(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletTransaction>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::RelevantLocations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_RelevantLocations(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsMoreTransactionHistoryLaunchable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_IsMoreTransactionHistoryLaunchable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::IsMoreTransactionHistoryLaunchable(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->put_IsMoreTransactionHistoryLaunchable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::DisplayProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_DisplayProperties(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletVerb>) consume_Windows_ApplicationModel_Wallet_IWalletItem<D>::Verbs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItem)->get_Verbs(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletVerb>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::Value(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::AutoDetectLinks() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_AutoDetectLinks(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::AutoDetectLinks(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_AutoDetectLinks(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::DetailViewPosition() const
    {
        winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_DetailViewPosition(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::DetailViewPosition(winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_DetailViewPosition(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::SummaryViewPosition() const
    {
        winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->get_SummaryViewPosition(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>::SummaryViewPosition(winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty)->put_SummaryViewPosition(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty) consume_Windows_ApplicationModel_Wallet_IWalletItemCustomPropertyFactory<D>::CreateWalletItemCustomProperty(param::hstring const& name, param::hstring const& value) const
    {
        void* walletItemCustomProperty{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory)->CreateWalletItemCustomProperty(*(void**)(&name), *(void**)(&value), &walletItemCustomProperty));
        return winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty{ walletItemCustomProperty, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletItem) consume_Windows_ApplicationModel_Wallet_IWalletItemFactory<D>::CreateWalletItem(winrt::Windows::ApplicationModel::Wallet::WalletItemKind const& kind, param::hstring const& displayName) const
    {
        void* walletItem{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory)->CreateWalletItem(static_cast<int32_t>(kind), *(void**)(&displayName), &walletItem));
        return winrt::Windows::ApplicationModel::Wallet::WalletItem{ walletItem, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::AddAsync(param::hstring const& id, winrt::Windows::ApplicationModel::Wallet::WalletItem const& item) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->AddAsync(*(void**)(&id), *(void**)(&item), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ClearAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->ClearAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::GetWalletItemAsync(param::hstring const& id) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->GetWalletItemAsync(*(void**)(&id), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::GetItemsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->GetItemsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::GetItemsAsync(winrt::Windows::ApplicationModel::Wallet::WalletItemKind const& kind) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->GetItemsWithKindAsync(static_cast<int32_t>(kind), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ImportItemAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->ImportItemAsync(*(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::DeleteAsync(param::hstring const& id) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->DeleteAsync(*(void**)(&id), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ShowAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->ShowAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::ShowAsync(param::hstring const& id) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->ShowItemAsync(*(void**)(&id), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>::UpdateAsync(winrt::Windows::ApplicationModel::Wallet::WalletItem const& item) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore)->UpdateAsync(*(void**)(&item), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Wallet::WalletItemStore, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2)->add_ItemsChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged_revoker consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Wallet::WalletItemStore, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ItemsChanged_revoker>(this, ItemsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>::ItemsChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2)->remove_ItemsChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>) consume_Windows_ApplicationModel_Wallet_IWalletManagerStatics<D>::RequestStoreAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics)->RequestStoreAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::BasicGeoposition) consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::Position() const
    {
        winrt::Windows::Devices::Geolocation::BasicGeoposition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::Position(winrt::Windows::Devices::Geolocation::BasicGeoposition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::DisplayMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->get_DisplayMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>::DisplayMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation)->put_DisplayMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayAmount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->get_DisplayAmount(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayAmount(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->put_DisplayAmount(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IgnoreTimeOfDay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->get_IgnoreTimeOfDay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IgnoreTimeOfDay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->put_IgnoreTimeOfDay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayLocation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->get_DisplayLocation(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::DisplayLocation(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->put_DisplayLocation(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::TransactionDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->get_TransactionDate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::TransactionDate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->put_TransactionDate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IsLaunchable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->get_IsLaunchable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>::IsLaunchable(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletTransaction)->put_IsLaunchable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Wallet_IWalletVerb<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletVerb)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Wallet_IWalletVerb<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletVerb)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletVerb) consume_Windows_ApplicationModel_Wallet_IWalletVerbFactory<D>::CreateWalletVerb(param::hstring const& name) const
    {
        void* WalletVerb{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory)->CreateWalletVerb(*(void**)(&name), &WalletVerb));
        return winrt::Windows::ApplicationModel::Wallet::WalletVerb{ WalletVerb, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletBarcode> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletBarcode>
    {
        int32_t __stdcall get_Symbology(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology>(this->shim().Symbology());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetImageAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>>(this->shim().GetImageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>
    {
        int32_t __stdcall CreateWalletBarcode(int32_t symbology, void* value, void** barcode) noexcept final try
        {
            clear_abi(barcode);
            typename D::abi_guard guard(this->shim());
            *barcode = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletBarcode>(this->shim().CreateWalletBarcode(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const*>(&symbology), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCustomWalletBarcode(void* streamToBarcodeImage, void** barcode) noexcept final try
        {
            clear_abi(barcode);
            typename D::abi_guard guard(this->shim());
            *barcode = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletBarcode>(this->shim().CreateCustomWalletBarcode(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&streamToBarcodeImage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletItem> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletItem>
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
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAcknowledged(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAcknowledged());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAcknowledged(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAcknowledged(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IssuerDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IssuerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IssuerDisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IssuerDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUpdated(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().LastUpdated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastUpdated(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastUpdated(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletItemKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Barcode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletBarcode>(this->shim().Barcode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Barcode(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Barcode(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletBarcode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationDate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationDate(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Logo159x159(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo159x159());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Logo159x159(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Logo159x159(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Logo336x336(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo336x336());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Logo336x336(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Logo336x336(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Logo99x99(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo99x99());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Logo99x99(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Logo99x99(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisplayMessageLaunchable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisplayMessageLaunchable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDisplayMessageLaunchable(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDisplayMessageLaunchable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogoText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LogoText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LogoText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogoText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().HeaderColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HeaderColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HeaderColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BodyColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BodyColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BodyColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BodyColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderFontColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().HeaderFontColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HeaderFontColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HeaderFontColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BodyFontColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BodyFontColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BodyFontColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BodyFontColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderBackgroundImage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().HeaderBackgroundImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HeaderBackgroundImage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HeaderBackgroundImage(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BodyBackgroundImage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().BodyBackgroundImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BodyBackgroundImage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BodyBackgroundImage(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogoImage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().LogoImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LogoImage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogoImage(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PromotionalImage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().PromotionalImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PromotionalImage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PromotionalImage(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelevantDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().RelevantDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelevantDate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelevantDate(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelevantDateDisplayMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RelevantDateDisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelevantDateDisplayMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelevantDateDisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransactionHistory(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletTransaction>>(this->shim().TransactionHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelevantLocations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation>>(this->shim().RelevantLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMoreTransactionHistoryLaunchable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMoreTransactionHistoryLaunchable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsMoreTransactionHistoryLaunchable(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMoreTransactionHistoryLaunchable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>>(this->shim().DisplayProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Verbs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletVerb>>(this->shim().Verbs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>
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
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoDetectLinks(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoDetectLinks());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoDetectLinks(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoDetectLinks(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DetailViewPosition(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition>(this->shim().DetailViewPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DetailViewPosition(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DetailViewPosition(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SummaryViewPosition(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition>(this->shim().SummaryViewPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SummaryViewPosition(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SummaryViewPosition(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>
    {
        int32_t __stdcall CreateWalletItemCustomProperty(void* name, void* value, void** walletItemCustomProperty) noexcept final try
        {
            clear_abi(walletItemCustomProperty);
            typename D::abi_guard guard(this->shim());
            *walletItemCustomProperty = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>(this->shim().CreateWalletItemCustomProperty(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory>
    {
        int32_t __stdcall CreateWalletItem(int32_t kind, void* displayName, void** walletItem) noexcept final try
        {
            clear_abi(walletItem);
            typename D::abi_guard guard(this->shim());
            *walletItem = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletItem>(this->shim().CreateWalletItem(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletItemKind const*>(&kind), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemStore> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemStore>
    {
        int32_t __stdcall AddAsync(void* id, void* item, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AddAsync(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ClearAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetWalletItemAsync(void* id, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>>(this->shim().GetWalletItemAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>>(this->shim().GetItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemsWithKindAsync(int32_t kind, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>>(this->shim().GetItemsAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletItemKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ImportItemAsync(void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>>(this->shim().ImportItemAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(void* id, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowItemAsync(void* id, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ShowAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateAsync(void* item, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpdateAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2>
    {
        int32_t __stdcall add_ItemsChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ItemsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Wallet::WalletItemStore, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemsChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemsChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics>
    {
        int32_t __stdcall RequestStoreAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation>
    {
        int32_t __stdcall get_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Geolocation::BasicGeoposition>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Geolocation::BasicGeoposition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Devices::Geolocation::BasicGeoposition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletTransaction> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletTransaction>
    {
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
        int32_t __stdcall get_DisplayAmount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayAmount(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayAmount(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IgnoreTimeOfDay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IgnoreTimeOfDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IgnoreTimeOfDay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IgnoreTimeOfDay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayLocation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayLocation(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayLocation(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransactionDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().TransactionDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransactionDate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransactionDate(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLaunchable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLaunchable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsLaunchable(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLaunchable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletVerb> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletVerb>
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
    struct produce<D, winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory> : produce_base<D, winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory>
    {
        int32_t __stdcall CreateWalletVerb(void* name, void** WalletVerb) noexcept final try
        {
            clear_abi(WalletVerb);
            typename D::abi_guard guard(this->shim());
            *WalletVerb = detach_from<winrt::Windows::ApplicationModel::Wallet::WalletVerb>(this->shim().CreateWalletVerb(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet
{
    inline WalletBarcode::WalletBarcode(winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const& symbology, param::hstring const& value) :
        WalletBarcode(impl::call_factory<WalletBarcode, IWalletBarcodeFactory>([&](IWalletBarcodeFactory const& f) { return f.CreateWalletBarcode(symbology, value); }))
    {
    }
    inline WalletBarcode::WalletBarcode(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& streamToBarcodeImage) :
        WalletBarcode(impl::call_factory<WalletBarcode, IWalletBarcodeFactory>([&](IWalletBarcodeFactory const& f) { return f.CreateCustomWalletBarcode(streamToBarcodeImage); }))
    {
    }
    inline WalletItem::WalletItem(winrt::Windows::ApplicationModel::Wallet::WalletItemKind const& kind, param::hstring const& displayName) :
        WalletItem(impl::call_factory<WalletItem, IWalletItemFactory>([&](IWalletItemFactory const& f) { return f.CreateWalletItem(kind, displayName); }))
    {
    }
    inline WalletItemCustomProperty::WalletItemCustomProperty(param::hstring const& name, param::hstring const& value) :
        WalletItemCustomProperty(impl::call_factory<WalletItemCustomProperty, IWalletItemCustomPropertyFactory>([&](IWalletItemCustomPropertyFactory const& f) { return f.CreateWalletItemCustomProperty(name, value); }))
    {
    }
    inline auto WalletManager::RequestStoreAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>(*)(IWalletManagerStatics const&), WalletManager, IWalletManagerStatics>([](IWalletManagerStatics const& f) { return f.RequestStoreAsync(); });
    }
    inline WalletRelevantLocation::WalletRelevantLocation() :
        WalletRelevantLocation(impl::call_factory_cast<WalletRelevantLocation(*)(winrt::Windows::Foundation::IActivationFactory const&), WalletRelevantLocation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WalletRelevantLocation>(); }))
    {
    }
    inline WalletTransaction::WalletTransaction() :
        WalletTransaction(impl::call_factory_cast<WalletTransaction(*)(winrt::Windows::Foundation::IActivationFactory const&), WalletTransaction>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WalletTransaction>(); }))
    {
    }
    inline WalletVerb::WalletVerb(param::hstring const& name) :
        WalletVerb(impl::call_factory<WalletVerb, IWalletVerbFactory>([&](IWalletVerbFactory const& f) { return f.CreateWalletVerb(name); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletVerb> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletBarcode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletItemStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletTransaction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Wallet::WalletVerb> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
