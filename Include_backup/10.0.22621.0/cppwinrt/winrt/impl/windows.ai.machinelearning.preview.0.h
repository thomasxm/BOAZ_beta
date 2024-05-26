// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_AI_MachineLearning_Preview_0_H
#define WINRT_Windows_AI_MachineLearning_Preview_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename K, typename V> struct __declspec(empty_bases) IMap;
    struct IPropertySet;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging
{
    enum class BitmapPixelFormat : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IRandomAccessStreamReference;
}
WINRT_EXPORT namespace winrt::Windows::AI::MachineLearning::Preview
{
    enum class FeatureElementKindPreview : int32_t
    {
        Undefined = 0,
        Float = 1,
        UInt8 = 2,
        Int8 = 3,
        UInt16 = 4,
        Int16 = 5,
        Int32 = 6,
        Int64 = 7,
        String = 8,
        Boolean = 9,
        Float16 = 10,
        Double = 11,
        UInt32 = 12,
        UInt64 = 13,
        Complex64 = 14,
        Complex128 = 15,
    };
    enum class LearningModelDeviceKindPreview : int32_t
    {
        LearningDeviceAny = 0,
        LearningDeviceCpu = 1,
        LearningDeviceGpu = 2,
        LearningDeviceNpu = 3,
        LearningDeviceDsp = 4,
        LearningDeviceFpga = 5,
    };
    enum class LearningModelFeatureKindPreview : int32_t
    {
        Undefined = 0,
        Tensor = 1,
        Sequence = 2,
        Map = 3,
        Image = 4,
    };
    struct IImageVariableDescriptorPreview;
    struct IInferencingOptionsPreview;
    struct ILearningModelBindingPreview;
    struct ILearningModelBindingPreviewFactory;
    struct ILearningModelDescriptionPreview;
    struct ILearningModelEvaluationResultPreview;
    struct ILearningModelPreview;
    struct ILearningModelPreviewStatics;
    struct ILearningModelVariableDescriptorPreview;
    struct IMapVariableDescriptorPreview;
    struct ISequenceVariableDescriptorPreview;
    struct ITensorVariableDescriptorPreview;
    struct ImageVariableDescriptorPreview;
    struct InferencingOptionsPreview;
    struct LearningModelBindingPreview;
    struct LearningModelDescriptionPreview;
    struct LearningModelEvaluationResultPreview;
    struct LearningModelPreview;
    struct LearningModelVariableDescriptorPreview;
    struct MapVariableDescriptorPreview;
    struct SequenceVariableDescriptorPreview;
    struct TensorVariableDescriptorPreview;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::ImageVariableDescriptorPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::InferencingOptionsPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelBindingPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelVariableDescriptorPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::MapVariableDescriptorPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::SequenceVariableDescriptorPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::TensorVariableDescriptorPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::FeatureElementKindPreview>{ using type = enum_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview>{ using type = enum_category; };
    template <> struct category<winrt::Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ImageVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.ImageVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::InferencingOptionsPreview> = L"Windows.AI.MachineLearning.Preview.InferencingOptionsPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelBindingPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelBindingPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelDescriptionPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelEvaluationResultPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::MapVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.MapVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::SequenceVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.SequenceVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::TensorVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.TensorVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::FeatureElementKindPreview> = L"Windows.AI.MachineLearning.Preview.FeatureElementKindPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelDeviceKindPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview> = L"Windows.AI.MachineLearning.Preview.LearningModelFeatureKindPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.IImageVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview> = L"Windows.AI.MachineLearning.Preview.IInferencingOptionsPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview> = L"Windows.AI.MachineLearning.Preview.ILearningModelBindingPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory> = L"Windows.AI.MachineLearning.Preview.ILearningModelBindingPreviewFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview> = L"Windows.AI.MachineLearning.Preview.ILearningModelDescriptionPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview> = L"Windows.AI.MachineLearning.Preview.ILearningModelEvaluationResultPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreview> = L"Windows.AI.MachineLearning.Preview.ILearningModelPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics> = L"Windows.AI.MachineLearning.Preview.ILearningModelPreviewStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.ILearningModelVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.IMapVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.ISequenceVariableDescriptorPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview> = L"Windows.AI.MachineLearning.Preview.ITensorVariableDescriptorPreview";
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>{ 0x7AE1FA72,0x029E,0x4DC5,{ 0xA2,0xF8,0x5F,0xB7,0x63,0x15,0x41,0x50 } }; // 7AE1FA72-029E-4DC5-A2F8-5FB763154150
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>{ 0x47BC8205,0x4D36,0x47A9,{ 0x8F,0x68,0xFF,0xCB,0x33,0x9D,0xD0,0xFC } }; // 47BC8205-4D36-47A9-8F68-FFCB339DD0FC
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>{ 0x93C901E8,0x6C78,0x4B4F,{ 0xAE,0xC1,0xA6,0xBB,0x9E,0x69,0x16,0x24 } }; // 93C901E8-6C78-4B4F-AEC1-A6BB9E691624
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>{ 0x48B8219F,0x1E51,0x4D77,{ 0xAE,0x50,0x3E,0xC1,0x64,0xAD,0x34,0x80 } }; // 48B8219F-1E51-4D77-AE50-3EC164AD3480
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>{ 0xF52C09C6,0x8611,0x40AD,{ 0x8E,0x59,0xDE,0x3F,0xD7,0x03,0x0A,0x40 } }; // F52C09C6-8611-40AD-8E59-DE3FD7030A40
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>{ 0xDF25EA9F,0x9863,0x4088,{ 0x84,0x98,0x87,0xA1,0xF4,0x68,0x6F,0x92 } }; // DF25EA9F-9863-4088-8498-87A1F4686F92
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreview>{ 0x049C266A,0x93B4,0x478C,{ 0xAE,0xB8,0x70,0x15,0x7B,0xF0,0xFF,0x94 } }; // 049C266A-93B4-478C-AEB8-70157BF0FF94
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>{ 0x164BBB60,0x8465,0x4786,{ 0x8B,0x93,0x2C,0x16,0xA8,0x92,0x89,0xD7 } }; // 164BBB60-8465-4786-8B93-2C16A89289D7
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>{ 0xB13DF682,0xFC30,0x492B,{ 0x8E,0xA0,0xED,0x1F,0x53,0xC0,0xB0,0x38 } }; // B13DF682-FC30-492B-8EA0-ED1F53C0B038
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>{ 0x3CB38370,0xC02B,0x4236,{ 0xB3,0xE8,0x6B,0xDC,0xA4,0x9C,0x31,0x29 } }; // 3CB38370-C02B-4236-B3E8-6BDCA49C3129
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>{ 0x9CD8F292,0x98B2,0x4530,{ 0xA1,0xB6,0x2D,0xED,0x5F,0xEC,0xBC,0x26 } }; // 9CD8F292-98B2-4530-A1B6-2DED5FECBC26
    template <> inline constexpr guid guid_v<winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>{ 0xA80F501A,0x9AAC,0x4233,{ 0x97,0x84,0xAC,0xEA,0xF9,0x25,0x10,0xB5 } }; // A80F501A-9AAC-4233-9784-ACEAF92510B5
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::ImageVariableDescriptorPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::InferencingOptionsPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::LearningModelBindingPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::LearningModelPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::LearningModelVariableDescriptorPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::MapVariableDescriptorPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::SequenceVariableDescriptorPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview; };
    template <> struct default_interface<winrt::Windows::AI::MachineLearning::Preview::TensorVariableDescriptorPreview>{ using type = winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview; };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_BitmapPixelFormat(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Width(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Height(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PreferredDeviceKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_PreferredDeviceKind(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsTracingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsTracingEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_MaxBatchSize(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_MinimizeMemoryAllocation(bool*) noexcept = 0;
            virtual int32_t __stdcall put_MinimizeMemoryAllocation(bool) noexcept = 0;
            virtual int32_t __stdcall get_ReclaimMemoryAfterEvaluation(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ReclaimMemoryAfterEvaluation(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Bind(void*, void*) noexcept = 0;
            virtual int32_t __stdcall BindWithProperties(void*, void*, void*) noexcept = 0;
            virtual int32_t __stdcall Clear() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromModel(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Author(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Domain(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_Version(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Metadata(void**) noexcept = 0;
            virtual int32_t __stdcall get_InputFeatures(void**) noexcept = 0;
            virtual int32_t __stdcall get_OutputFeatures(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CorrelationId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Outputs(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall EvaluateAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall EvaluateFeaturesAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_InferencingOptions(void**) noexcept = 0;
            virtual int32_t __stdcall put_InferencingOptions(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall LoadModelFromStorageFileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadModelFromStreamAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_ModelFeatureKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsRequired(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_KeyKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ValidStringKeys(void**) noexcept = 0;
            virtual int32_t __stdcall get_ValidIntegerKeys(void**) noexcept = 0;
            virtual int32_t __stdcall get_Fields(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ElementType(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DataType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Shape(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_IImageVariableDescriptorPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapPixelFormat) BitmapPixelFormat() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Width() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Height() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::IImageVariableDescriptorPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_IImageVariableDescriptorPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_IInferencingOptionsPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview) PreferredDeviceKind() const;
        WINRT_IMPL_AUTO(void) PreferredDeviceKind(winrt::Windows::AI::MachineLearning::Preview::LearningModelDeviceKindPreview const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTracingEnabled() const;
        WINRT_IMPL_AUTO(void) IsTracingEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) MaxBatchSize() const;
        WINRT_IMPL_AUTO(void) MaxBatchSize(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) MinimizeMemoryAllocation() const;
        WINRT_IMPL_AUTO(void) MinimizeMemoryAllocation(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ReclaimMemoryAfterEvaluation() const;
        WINRT_IMPL_AUTO(void) ReclaimMemoryAfterEvaluation(bool value) const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::IInferencingOptionsPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_IInferencingOptionsPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreview
    {
        WINRT_IMPL_AUTO(void) Bind(param::hstring const& name, winrt::Windows::Foundation::IInspectable const& value) const;
        WINRT_IMPL_AUTO(void) Bind(param::hstring const& name, winrt::Windows::Foundation::IInspectable const& value, winrt::Windows::Foundation::Collections::IPropertySet const& metadata) const;
        WINRT_IMPL_AUTO(void) Clear() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreviewFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::LearningModelBindingPreview) CreateFromModel(winrt::Windows::AI::MachineLearning::Preview::LearningModelPreview const& model) const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelBindingPreviewFactory>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelBindingPreviewFactory<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelDescriptionPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Author() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Domain() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int64_t) Version() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) Metadata() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>) InputFeatures() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>) OutputFeatures() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelDescriptionPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelDescriptionPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelEvaluationResultPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CorrelationId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Outputs() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelEvaluationResultPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelEvaluationResultPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelPreview
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>) EvaluateAsync(winrt::Windows::AI::MachineLearning::Preview::LearningModelBindingPreview const& binding, param::hstring const& correlationId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::AI::MachineLearning::Preview::LearningModelEvaluationResultPreview>) EvaluateFeaturesAsync(param::map<hstring, winrt::Windows::Foundation::IInspectable> const& features, param::hstring const& correlationId) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::LearningModelDescriptionPreview) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::InferencingOptionsPreview) InferencingOptions() const;
        WINRT_IMPL_AUTO(void) InferencingOptions(winrt::Windows::AI::MachineLearning::Preview::InferencingOptionsPreview const& value) const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelPreviewStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::AI::MachineLearning::Preview::LearningModelPreview>) LoadModelFromStorageFileAsync(winrt::Windows::Storage::IStorageFile const& modelFile) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::AI::MachineLearning::Preview::LearningModelPreview>) LoadModelFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& modelStream) const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelPreviewStatics>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelPreviewStatics<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ILearningModelVariableDescriptorPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::LearningModelFeatureKindPreview) ModelFeatureKind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRequired() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ILearningModelVariableDescriptorPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_IMapVariableDescriptorPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::FeatureElementKindPreview) KeyKind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<hstring>) ValidStringKeys() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<int64_t>) ValidIntegerKeys() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview) Fields() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::IMapVariableDescriptorPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_IMapVariableDescriptorPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ISequenceVariableDescriptorPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::ILearningModelVariableDescriptorPreview) ElementType() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ISequenceVariableDescriptorPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ISequenceVariableDescriptorPreview<D>;
    };
    template <typename D>
    struct consume_Windows_AI_MachineLearning_Preview_ITensorVariableDescriptorPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::AI::MachineLearning::Preview::FeatureElementKindPreview) DataType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<int64_t>) Shape() const;
    };
    template <> struct consume<winrt::Windows::AI::MachineLearning::Preview::ITensorVariableDescriptorPreview>
    {
        template <typename D> using type = consume_Windows_AI_MachineLearning_Preview_ITensorVariableDescriptorPreview<D>;
    };
}
#endif
