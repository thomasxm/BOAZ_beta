// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Search_1_H
#define WINRT_Windows_ApplicationModel_Search_1_H
#include "winrt/impl/Windows.ApplicationModel.Search.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search
{
    struct __declspec(empty_bases) ILocalContentSuggestionSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILocalContentSuggestionSettings>
    {
        ILocalContentSuggestionSettings(std::nullptr_t = nullptr) noexcept {}
        ILocalContentSuggestionSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPane :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPane>
    {
        ISearchPane(std::nullptr_t = nullptr) noexcept {}
        ISearchPane(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneQueryChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneQueryChangedEventArgs>
    {
        ISearchPaneQueryChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneQueryChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneQueryLinguisticDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneQueryLinguisticDetails>
    {
        ISearchPaneQueryLinguisticDetails(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneQueryLinguisticDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneQuerySubmittedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneQuerySubmittedEventArgs>
    {
        ISearchPaneQuerySubmittedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneQuerySubmittedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails>
    {
        ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneResultSuggestionChosenEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneResultSuggestionChosenEventArgs>
    {
        ISearchPaneResultSuggestionChosenEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneResultSuggestionChosenEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneStatics>
    {
        ISearchPaneStatics(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneStaticsWithHideThisApplication :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneStaticsWithHideThisApplication>
    {
        ISearchPaneStaticsWithHideThisApplication(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneStaticsWithHideThisApplication(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneSuggestionsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneSuggestionsRequest>
    {
        ISearchPaneSuggestionsRequest(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneSuggestionsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneSuggestionsRequestDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneSuggestionsRequestDeferral>
    {
        ISearchPaneSuggestionsRequestDeferral(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneSuggestionsRequestDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneSuggestionsRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneSuggestionsRequestedEventArgs>,
        impl::require<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs, winrt::Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs>
    {
        ISearchPaneSuggestionsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneSuggestionsRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchPaneVisibilityChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchPaneVisibilityChangedEventArgs>
    {
        ISearchPaneVisibilityChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISearchPaneVisibilityChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchQueryLinguisticDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchQueryLinguisticDetails>
    {
        ISearchQueryLinguisticDetails(std::nullptr_t = nullptr) noexcept {}
        ISearchQueryLinguisticDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchQueryLinguisticDetailsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchQueryLinguisticDetailsFactory>
    {
        ISearchQueryLinguisticDetailsFactory(std::nullptr_t = nullptr) noexcept {}
        ISearchQueryLinguisticDetailsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchSuggestionCollection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchSuggestionCollection>
    {
        ISearchSuggestionCollection(std::nullptr_t = nullptr) noexcept {}
        ISearchSuggestionCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchSuggestionsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchSuggestionsRequest>
    {
        ISearchSuggestionsRequest(std::nullptr_t = nullptr) noexcept {}
        ISearchSuggestionsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISearchSuggestionsRequestDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISearchSuggestionsRequestDeferral>
    {
        ISearchSuggestionsRequestDeferral(std::nullptr_t = nullptr) noexcept {}
        ISearchSuggestionsRequestDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
