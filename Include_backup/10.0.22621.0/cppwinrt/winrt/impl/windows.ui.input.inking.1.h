// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_1_H
#define WINRT_Windows_UI_Input_Inking_1_H
#include "winrt/impl/Windows.UI.Input.Inking.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking
{
    struct __declspec(empty_bases) IInkDrawingAttributes :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributes>
    {
        IInkDrawingAttributes(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributes(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkDrawingAttributes2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributes2>
    {
        IInkDrawingAttributes2(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributes2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkDrawingAttributes3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributes3>
    {
        IInkDrawingAttributes3(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributes3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkDrawingAttributes4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributes4>
    {
        IInkDrawingAttributes4(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributes4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkDrawingAttributes5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributes5>
    {
        IInkDrawingAttributes5(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributes5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkDrawingAttributesPencilProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributesPencilProperties>
    {
        IInkDrawingAttributesPencilProperties(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributesPencilProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkDrawingAttributesStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkDrawingAttributesStatics>
    {
        IInkDrawingAttributesStatics(std::nullptr_t = nullptr) noexcept {}
        IInkDrawingAttributesStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkInputConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkInputConfiguration>
    {
        IInkInputConfiguration(std::nullptr_t = nullptr) noexcept {}
        IInkInputConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkInputConfiguration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkInputConfiguration2>
    {
        IInkInputConfiguration2(std::nullptr_t = nullptr) noexcept {}
        IInkInputConfiguration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkInputProcessingConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkInputProcessingConfiguration>
    {
        IInkInputProcessingConfiguration(std::nullptr_t = nullptr) noexcept {}
        IInkInputProcessingConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkManager>,
        impl::require<winrt::Windows::UI::Input::Inking::IInkManager, winrt::Windows::UI::Input::Inking::IInkStrokeContainer, winrt::Windows::UI::Input::Inking::IInkRecognizerContainer>
    {
        IInkManager(std::nullptr_t = nullptr) noexcept {}
        IInkManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IInkManager, IInkManager>::RecognizeAsync;
        using impl::consume_t<IInkManager, winrt::Windows::UI::Input::Inking::IInkRecognizerContainer>::RecognizeAsync;
    };
    struct __declspec(empty_bases) IInkModelerAttributes :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkModelerAttributes>
    {
        IInkModelerAttributes(std::nullptr_t = nullptr) noexcept {}
        IInkModelerAttributes(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkModelerAttributes2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkModelerAttributes2>
    {
        IInkModelerAttributes2(std::nullptr_t = nullptr) noexcept {}
        IInkModelerAttributes2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPoint :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPoint>
    {
        IInkPoint(std::nullptr_t = nullptr) noexcept {}
        IInkPoint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPoint2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPoint2>
    {
        IInkPoint2(std::nullptr_t = nullptr) noexcept {}
        IInkPoint2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPointFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPointFactory>
    {
        IInkPointFactory(std::nullptr_t = nullptr) noexcept {}
        IInkPointFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPointFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPointFactory2>
    {
        IInkPointFactory2(std::nullptr_t = nullptr) noexcept {}
        IInkPointFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenter>
    {
        IInkPresenter(std::nullptr_t = nullptr) noexcept {}
        IInkPresenter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenter2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenter2>,
        impl::require<winrt::Windows::UI::Input::Inking::IInkPresenter2, winrt::Windows::UI::Input::Inking::IInkPresenter>
    {
        IInkPresenter2(std::nullptr_t = nullptr) noexcept {}
        IInkPresenter2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenter3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenter3>
    {
        IInkPresenter3(std::nullptr_t = nullptr) noexcept {}
        IInkPresenter3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenterProtractor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenterProtractor>,
        impl::require<winrt::Windows::UI::Input::Inking::IInkPresenterProtractor, winrt::Windows::UI::Input::Inking::IInkPresenterStencil>
    {
        IInkPresenterProtractor(std::nullptr_t = nullptr) noexcept {}
        IInkPresenterProtractor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenterProtractorFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenterProtractorFactory>
    {
        IInkPresenterProtractorFactory(std::nullptr_t = nullptr) noexcept {}
        IInkPresenterProtractorFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenterRuler :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenterRuler>,
        impl::require<winrt::Windows::UI::Input::Inking::IInkPresenterRuler, winrt::Windows::UI::Input::Inking::IInkPresenterStencil>
    {
        IInkPresenterRuler(std::nullptr_t = nullptr) noexcept {}
        IInkPresenterRuler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenterRuler2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenterRuler2>
    {
        IInkPresenterRuler2(std::nullptr_t = nullptr) noexcept {}
        IInkPresenterRuler2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenterRulerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenterRulerFactory>
    {
        IInkPresenterRulerFactory(std::nullptr_t = nullptr) noexcept {}
        IInkPresenterRulerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkPresenterStencil :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkPresenterStencil>
    {
        IInkPresenterStencil(std::nullptr_t = nullptr) noexcept {}
        IInkPresenterStencil(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkRecognitionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkRecognitionResult>
    {
        IInkRecognitionResult(std::nullptr_t = nullptr) noexcept {}
        IInkRecognitionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkRecognizer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkRecognizer>
    {
        IInkRecognizer(std::nullptr_t = nullptr) noexcept {}
        IInkRecognizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkRecognizerContainer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkRecognizerContainer>
    {
        IInkRecognizerContainer(std::nullptr_t = nullptr) noexcept {}
        IInkRecognizerContainer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStroke :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStroke>
    {
        IInkStroke(std::nullptr_t = nullptr) noexcept {}
        IInkStroke(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStroke2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStroke2>
    {
        IInkStroke2(std::nullptr_t = nullptr) noexcept {}
        IInkStroke2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStroke3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStroke3>
    {
        IInkStroke3(std::nullptr_t = nullptr) noexcept {}
        IInkStroke3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStroke4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStroke4>
    {
        IInkStroke4(std::nullptr_t = nullptr) noexcept {}
        IInkStroke4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeBuilder :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeBuilder>
    {
        IInkStrokeBuilder(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeBuilder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeBuilder2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeBuilder2>
    {
        IInkStrokeBuilder2(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeBuilder2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeBuilder3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeBuilder3>
    {
        IInkStrokeBuilder3(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeBuilder3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeContainer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeContainer>
    {
        IInkStrokeContainer(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeContainer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeContainer2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeContainer2>
    {
        IInkStrokeContainer2(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeContainer2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeContainer3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeContainer3>
    {
        IInkStrokeContainer3(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeContainer3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeInput :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeInput>
    {
        IInkStrokeInput(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokeRenderingSegment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokeRenderingSegment>
    {
        IInkStrokeRenderingSegment(std::nullptr_t = nullptr) noexcept {}
        IInkStrokeRenderingSegment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokesCollectedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokesCollectedEventArgs>
    {
        IInkStrokesCollectedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IInkStrokesCollectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkStrokesErasedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkStrokesErasedEventArgs>
    {
        IInkStrokesErasedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IInkStrokesErasedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkSynchronizer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkSynchronizer>
    {
        IInkSynchronizer(std::nullptr_t = nullptr) noexcept {}
        IInkSynchronizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkUnprocessedInput :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkUnprocessedInput>
    {
        IInkUnprocessedInput(std::nullptr_t = nullptr) noexcept {}
        IInkUnprocessedInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenAndInkSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenAndInkSettings>
    {
        IPenAndInkSettings(std::nullptr_t = nullptr) noexcept {}
        IPenAndInkSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenAndInkSettings2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenAndInkSettings2>
    {
        IPenAndInkSettings2(std::nullptr_t = nullptr) noexcept {}
        IPenAndInkSettings2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenAndInkSettingsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenAndInkSettingsStatics>
    {
        IPenAndInkSettingsStatics(std::nullptr_t = nullptr) noexcept {}
        IPenAndInkSettingsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
