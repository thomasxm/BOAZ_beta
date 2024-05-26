// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_Analysis_1_H
#define WINRT_Windows_UI_Input_Inking_Analysis_1_H
#include "winrt/impl/Windows.UI.Input.Inking.Analysis.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Analysis
{
    struct __declspec(empty_bases) IInkAnalysisInkBullet :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisInkBullet>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisInkBullet(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisInkBullet(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisInkDrawing :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisInkDrawing>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisInkDrawing(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisInkDrawing(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisInkWord :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisInkWord>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisInkWord(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisInkWord(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisLine :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisLine>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisLine(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisLine(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisListItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisListItem>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisListItem(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisListItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisNode>
    {
        IInkAnalysisNode(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisParagraph :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisParagraph>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisParagraph(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisParagraph(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisResult>
    {
        IInkAnalysisResult(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisRoot :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisRoot>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisRoot(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisRoot(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalysisWritingRegion :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalysisWritingRegion>,
        impl::require<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        IInkAnalysisWritingRegion(std::nullptr_t = nullptr) noexcept {}
        IInkAnalysisWritingRegion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalyzer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalyzer>
    {
        IInkAnalyzer(std::nullptr_t = nullptr) noexcept {}
        IInkAnalyzer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkAnalyzerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkAnalyzerFactory>
    {
        IInkAnalyzerFactory(std::nullptr_t = nullptr) noexcept {}
        IInkAnalyzerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
