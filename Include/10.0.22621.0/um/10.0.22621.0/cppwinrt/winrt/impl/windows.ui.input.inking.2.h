// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_2_H
#define WINRT_Windows_UI_Input_Inking_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Input.Inking.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking
{
    struct __declspec(empty_bases) InkDrawingAttributes : winrt::Windows::UI::Input::Inking::IInkDrawingAttributes,
        impl::require<InkDrawingAttributes, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5>
    {
        InkDrawingAttributes(std::nullptr_t) noexcept {}
        InkDrawingAttributes(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkDrawingAttributes(ptr, take_ownership_from_abi) {}
        InkDrawingAttributes();
        static auto CreateForPencil();
    };
    struct __declspec(empty_bases) InkDrawingAttributesPencilProperties : winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties
    {
        InkDrawingAttributesPencilProperties(std::nullptr_t) noexcept {}
        InkDrawingAttributesPencilProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkInputConfiguration : winrt::Windows::UI::Input::Inking::IInkInputConfiguration,
        impl::require<InkInputConfiguration, winrt::Windows::UI::Input::Inking::IInkInputConfiguration2>
    {
        InkInputConfiguration(std::nullptr_t) noexcept {}
        InkInputConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkInputConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkInputProcessingConfiguration : winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration
    {
        InkInputProcessingConfiguration(std::nullptr_t) noexcept {}
        InkInputProcessingConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkManager : winrt::Windows::UI::Input::Inking::IInkManager
    {
        InkManager(std::nullptr_t) noexcept {}
        InkManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkManager(ptr, take_ownership_from_abi) {}
        InkManager();
    };
    struct __declspec(empty_bases) InkModelerAttributes : winrt::Windows::UI::Input::Inking::IInkModelerAttributes,
        impl::require<InkModelerAttributes, winrt::Windows::UI::Input::Inking::IInkModelerAttributes2>
    {
        InkModelerAttributes(std::nullptr_t) noexcept {}
        InkModelerAttributes(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkModelerAttributes(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkPoint : winrt::Windows::UI::Input::Inking::IInkPoint,
        impl::require<InkPoint, winrt::Windows::UI::Input::Inking::IInkPoint2>
    {
        InkPoint(std::nullptr_t) noexcept {}
        InkPoint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkPoint(ptr, take_ownership_from_abi) {}
        InkPoint(winrt::Windows::Foundation::Point const& position, float pressure);
        InkPoint(winrt::Windows::Foundation::Point const& position, float pressure, float tiltX, float tiltY, uint64_t timestamp);
    };
    struct __declspec(empty_bases) InkPresenter : winrt::Windows::UI::Input::Inking::IInkPresenter,
        impl::require<InkPresenter, winrt::Windows::UI::Input::Inking::IInkPresenter2, winrt::Windows::UI::Input::Inking::IInkPresenter3>
    {
        InkPresenter(std::nullptr_t) noexcept {}
        InkPresenter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkPresenter(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkPresenterProtractor : winrt::Windows::UI::Input::Inking::IInkPresenterProtractor
    {
        InkPresenterProtractor(std::nullptr_t) noexcept {}
        InkPresenterProtractor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkPresenterProtractor(ptr, take_ownership_from_abi) {}
        explicit InkPresenterProtractor(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter);
    };
    struct __declspec(empty_bases) InkPresenterRuler : winrt::Windows::UI::Input::Inking::IInkPresenterRuler,
        impl::require<InkPresenterRuler, winrt::Windows::UI::Input::Inking::IInkPresenterRuler2>
    {
        InkPresenterRuler(std::nullptr_t) noexcept {}
        InkPresenterRuler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkPresenterRuler(ptr, take_ownership_from_abi) {}
        explicit InkPresenterRuler(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter);
    };
    struct __declspec(empty_bases) InkRecognitionResult : winrt::Windows::UI::Input::Inking::IInkRecognitionResult
    {
        InkRecognitionResult(std::nullptr_t) noexcept {}
        InkRecognitionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkRecognitionResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkRecognizer : winrt::Windows::UI::Input::Inking::IInkRecognizer
    {
        InkRecognizer(std::nullptr_t) noexcept {}
        InkRecognizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkRecognizer(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkRecognizerContainer : winrt::Windows::UI::Input::Inking::IInkRecognizerContainer
    {
        InkRecognizerContainer(std::nullptr_t) noexcept {}
        InkRecognizerContainer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkRecognizerContainer(ptr, take_ownership_from_abi) {}
        InkRecognizerContainer();
    };
    struct __declspec(empty_bases) InkStroke : winrt::Windows::UI::Input::Inking::IInkStroke,
        impl::require<InkStroke, winrt::Windows::UI::Input::Inking::IInkStroke2, winrt::Windows::UI::Input::Inking::IInkStroke3, winrt::Windows::UI::Input::Inking::IInkStroke4>
    {
        InkStroke(std::nullptr_t) noexcept {}
        InkStroke(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStroke(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkStrokeBuilder : winrt::Windows::UI::Input::Inking::IInkStrokeBuilder,
        impl::require<InkStrokeBuilder, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3>
    {
        InkStrokeBuilder(std::nullptr_t) noexcept {}
        InkStrokeBuilder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStrokeBuilder(ptr, take_ownership_from_abi) {}
        InkStrokeBuilder();
        using impl::consume_t<InkStrokeBuilder, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2>::CreateStrokeFromInkPoints;
        using impl::consume_t<InkStrokeBuilder, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3>::CreateStrokeFromInkPoints;
    };
    struct __declspec(empty_bases) InkStrokeContainer : winrt::Windows::UI::Input::Inking::IInkStrokeContainer,
        impl::require<InkStrokeContainer, winrt::Windows::UI::Input::Inking::IInkStrokeContainer2, winrt::Windows::UI::Input::Inking::IInkStrokeContainer3>
    {
        InkStrokeContainer(std::nullptr_t) noexcept {}
        InkStrokeContainer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStrokeContainer(ptr, take_ownership_from_abi) {}
        InkStrokeContainer();
        using winrt::Windows::UI::Input::Inking::IInkStrokeContainer::SaveAsync;
        using impl::consume_t<InkStrokeContainer, winrt::Windows::UI::Input::Inking::IInkStrokeContainer3>::SaveAsync;
    };
    struct __declspec(empty_bases) InkStrokeInput : winrt::Windows::UI::Input::Inking::IInkStrokeInput
    {
        InkStrokeInput(std::nullptr_t) noexcept {}
        InkStrokeInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStrokeInput(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkStrokeRenderingSegment : winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment
    {
        InkStrokeRenderingSegment(std::nullptr_t) noexcept {}
        InkStrokeRenderingSegment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkStrokesCollectedEventArgs : winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs
    {
        InkStrokesCollectedEventArgs(std::nullptr_t) noexcept {}
        InkStrokesCollectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkStrokesErasedEventArgs : winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs
    {
        InkStrokesErasedEventArgs(std::nullptr_t) noexcept {}
        InkStrokesErasedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkSynchronizer : winrt::Windows::UI::Input::Inking::IInkSynchronizer
    {
        InkSynchronizer(std::nullptr_t) noexcept {}
        InkSynchronizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkSynchronizer(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InkUnprocessedInput : winrt::Windows::UI::Input::Inking::IInkUnprocessedInput
    {
        InkUnprocessedInput(std::nullptr_t) noexcept {}
        InkUnprocessedInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IInkUnprocessedInput(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PenAndInkSettings : winrt::Windows::UI::Input::Inking::IPenAndInkSettings,
        impl::require<PenAndInkSettings, winrt::Windows::UI::Input::Inking::IPenAndInkSettings2>
    {
        PenAndInkSettings(std::nullptr_t) noexcept {}
        PenAndInkSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::IPenAndInkSettings(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
    };
}
#endif
