// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_2_H
#define WINRT_Windows_ApplicationModel_DataTransfer_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer
{
    struct DataProviderHandler : winrt::Windows::Foundation::IUnknown
    {
        DataProviderHandler(std::nullptr_t = nullptr) noexcept {}
        DataProviderHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> DataProviderHandler(L lambda);
        template <typename F> DataProviderHandler(F* function);
        template <typename O, typename M> DataProviderHandler(O* object, M method);
        template <typename O, typename M> DataProviderHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> DataProviderHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::ApplicationModel::DataTransfer::DataProviderRequest const& request) const;
    };
    struct ShareProviderHandler : winrt::Windows::Foundation::IUnknown
    {
        ShareProviderHandler(std::nullptr_t = nullptr) noexcept {}
        ShareProviderHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> ShareProviderHandler(L lambda);
        template <typename F> ShareProviderHandler(F* function);
        template <typename O, typename M> ShareProviderHandler(O* object, M method);
        template <typename O, typename M> ShareProviderHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> ShareProviderHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::ApplicationModel::DataTransfer::ShareProviderOperation const& operation) const;
    };
    struct Clipboard
    {
        Clipboard() = delete;
        static auto GetContent();
        static auto SetContent(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& content);
        static auto Flush();
        static auto Clear();
        static auto ContentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using ContentChanged_revoker = impl::factory_event_revoker<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics, &impl::abi_t<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics>::remove_ContentChanged>;
        [[nodiscard]] static ContentChanged_revoker ContentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto ContentChanged(winrt::event_token const& token);
        static auto GetHistoryItemsAsync();
        static auto ClearHistory();
        static auto DeleteItemFromHistory(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item);
        static auto SetHistoryItemAsContent(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item);
        static auto IsHistoryEnabled();
        static auto IsRoamingEnabled();
        static auto SetContentWithOptions(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& content, winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options);
        static auto HistoryChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler);
        using HistoryChanged_revoker = impl::factory_event_revoker<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_HistoryChanged>;
        [[nodiscard]] static HistoryChanged_revoker HistoryChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler);
        static auto HistoryChanged(winrt::event_token const& token);
        static auto RoamingEnabledChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RoamingEnabledChanged_revoker = impl::factory_event_revoker<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_RoamingEnabledChanged>;
        [[nodiscard]] static RoamingEnabledChanged_revoker RoamingEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RoamingEnabledChanged(winrt::event_token const& token);
        static auto HistoryEnabledChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using HistoryEnabledChanged_revoker = impl::factory_event_revoker<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_HistoryEnabledChanged>;
        [[nodiscard]] static HistoryEnabledChanged_revoker HistoryEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto HistoryEnabledChanged(winrt::event_token const& token);
    };
    struct __declspec(empty_bases) ClipboardContentOptions : winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions
    {
        ClipboardContentOptions(std::nullptr_t) noexcept {}
        ClipboardContentOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions(ptr, take_ownership_from_abi) {}
        ClipboardContentOptions();
    };
    struct __declspec(empty_bases) ClipboardHistoryChangedEventArgs : winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs
    {
        ClipboardHistoryChangedEventArgs(std::nullptr_t) noexcept {}
        ClipboardHistoryChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ClipboardHistoryItem : winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem
    {
        ClipboardHistoryItem(std::nullptr_t) noexcept {}
        ClipboardHistoryItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ClipboardHistoryItemsResult : winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult
    {
        ClipboardHistoryItemsResult(std::nullptr_t) noexcept {}
        ClipboardHistoryItemsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataPackage : winrt::Windows::ApplicationModel::DataTransfer::IDataPackage,
        impl::require<DataPackage, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage4>
    {
        DataPackage(std::nullptr_t) noexcept {}
        DataPackage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataPackage(ptr, take_ownership_from_abi) {}
        DataPackage();
    };
    struct __declspec(empty_bases) DataPackagePropertySet : winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet,
        impl::require<DataPackagePropertySet, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>
    {
        DataPackagePropertySet(std::nullptr_t) noexcept {}
        DataPackagePropertySet(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataPackagePropertySetView : winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView,
        impl::require<DataPackagePropertySetView, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Foundation::IInspectable>>, winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>
    {
        DataPackagePropertySetView(std::nullptr_t) noexcept {}
        DataPackagePropertySetView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataPackageView : winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView,
        impl::require<DataPackageView, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4>
    {
        DataPackageView(std::nullptr_t) noexcept {}
        DataPackageView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataProviderDeferral : winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral
    {
        DataProviderDeferral(std::nullptr_t) noexcept {}
        DataProviderDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataProviderRequest : winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest
    {
        DataProviderRequest(std::nullptr_t) noexcept {}
        DataProviderRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataRequest : winrt::Windows::ApplicationModel::DataTransfer::IDataRequest
    {
        DataRequest(std::nullptr_t) noexcept {}
        DataRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataRequest(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataRequestDeferral : winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral
    {
        DataRequestDeferral(std::nullptr_t) noexcept {}
        DataRequestDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataRequestedEventArgs : winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs
    {
        DataRequestedEventArgs(std::nullptr_t) noexcept {}
        DataRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DataTransferManager : winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager,
        impl::require<DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2>
    {
        DataTransferManager(std::nullptr_t) noexcept {}
        DataTransferManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager(ptr, take_ownership_from_abi) {}
        static auto ShowShareUI();
        static auto GetForCurrentView();
        static auto IsSupported();
        static auto ShowShareUI(winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options);
    };
    struct HtmlFormatHelper
    {
        HtmlFormatHelper() = delete;
        static auto GetStaticFragment(param::hstring const& htmlFormat);
        static auto CreateHtmlFormat(param::hstring const& htmlFragment);
    };
    struct __declspec(empty_bases) OperationCompletedEventArgs : winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs,
        impl::require<OperationCompletedEventArgs, winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>
    {
        OperationCompletedEventArgs(std::nullptr_t) noexcept {}
        OperationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareCompletedEventArgs : winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs
    {
        ShareCompletedEventArgs(std::nullptr_t) noexcept {}
        ShareCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareProvider : winrt::Windows::ApplicationModel::DataTransfer::IShareProvider
    {
        ShareProvider(std::nullptr_t) noexcept {}
        ShareProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IShareProvider(ptr, take_ownership_from_abi) {}
        ShareProvider(param::hstring const& title, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, winrt::Windows::UI::Color const& backgroundColor, winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler);
    };
    struct __declspec(empty_bases) ShareProviderOperation : winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation
    {
        ShareProviderOperation(std::nullptr_t) noexcept {}
        ShareProviderOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareProvidersRequestedEventArgs : winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs
    {
        ShareProvidersRequestedEventArgs(std::nullptr_t) noexcept {}
        ShareProvidersRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareTargetInfo : winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo
    {
        ShareTargetInfo(std::nullptr_t) noexcept {}
        ShareTargetInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareUIOptions : winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions
    {
        ShareUIOptions(std::nullptr_t) noexcept {}
        ShareUIOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions(ptr, take_ownership_from_abi) {}
        ShareUIOptions();
    };
    struct SharedStorageAccessManager
    {
        SharedStorageAccessManager() = delete;
        static auto AddFile(winrt::Windows::Storage::IStorageFile const& file);
        static auto RedeemTokenForFileAsync(param::hstring const& token);
        static auto RemoveFile(param::hstring const& token);
    };
    struct StandardDataFormats
    {
        StandardDataFormats() = delete;
        [[nodiscard]] static auto Text();
        [[nodiscard]] static auto Uri();
        [[nodiscard]] static auto Html();
        [[nodiscard]] static auto Rtf();
        [[nodiscard]] static auto Bitmap();
        [[nodiscard]] static auto StorageItems();
        [[nodiscard]] static auto WebLink();
        [[nodiscard]] static auto ApplicationLink();
        [[nodiscard]] static auto UserActivityJsonArray();
    };
    struct __declspec(empty_bases) TargetApplicationChosenEventArgs : winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs
    {
        TargetApplicationChosenEventArgs(std::nullptr_t) noexcept {}
        TargetApplicationChosenEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
