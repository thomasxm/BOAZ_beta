// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_AI_MachineLearning_Preview_1_H
#define WINRT_Windows_AI_MachineLearning_Preview_1_H
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.AI.MachineLearning.Preview.0.h"
WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning::Preview
{
    struct __declspec(empty_bases) IImageVariableDescriptorPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageVariableDescriptorPreview>,
        impl::require<winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview, winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
    {
        IImageVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
        IImageVariableDescriptorPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInferencingOptionsPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInferencingOptionsPreview>
    {
        IInferencingOptionsPreview(std::nullptr_t = nullptr) noexcept {}
        IInferencingOptionsPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelBindingPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelBindingPreview>,
        impl::require<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Foundation::IInspectable>>, winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>
    {
        ILearningModelBindingPreview(std::nullptr_t = nullptr) noexcept {}
        ILearningModelBindingPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelBindingPreviewFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelBindingPreviewFactory>
    {
        ILearningModelBindingPreviewFactory(std::nullptr_t = nullptr) noexcept {}
        ILearningModelBindingPreviewFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelDescriptionPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelDescriptionPreview>
    {
        ILearningModelDescriptionPreview(std::nullptr_t = nullptr) noexcept {}
        ILearningModelDescriptionPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelEvaluationResultPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelEvaluationResultPreview>
    {
        ILearningModelEvaluationResultPreview(std::nullptr_t = nullptr) noexcept {}
        ILearningModelEvaluationResultPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelPreview>
    {
        ILearningModelPreview(std::nullptr_t = nullptr) noexcept {}
        ILearningModelPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelPreviewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelPreviewStatics>
    {
        ILearningModelPreviewStatics(std::nullptr_t = nullptr) noexcept {}
        ILearningModelPreviewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILearningModelVariableDescriptorPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILearningModelVariableDescriptorPreview>
    {
        ILearningModelVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
        ILearningModelVariableDescriptorPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMapVariableDescriptorPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMapVariableDescriptorPreview>,
        impl::require<winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview, winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
    {
        IMapVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
        IMapVariableDescriptorPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISequenceVariableDescriptorPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISequenceVariableDescriptorPreview>,
        impl::require<winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview, winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
    {
        ISequenceVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
        ISequenceVariableDescriptorPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITensorVariableDescriptorPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITensorVariableDescriptorPreview>,
        impl::require<winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview, winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
    {
        ITensorVariableDescriptorPreview(std::nullptr_t = nullptr) noexcept {}
        ITensorVariableDescriptorPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
