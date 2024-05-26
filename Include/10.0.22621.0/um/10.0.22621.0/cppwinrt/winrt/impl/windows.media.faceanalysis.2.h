// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_FaceAnalysis_2_H
#define WINRT_Windows_Media_FaceAnalysis_2_H
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Media.FaceAnalysis.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::FaceAnalysis
{
    struct __declspec(empty_bases) DetectedFace : winrt::Windows::Media::FaceAnalysis::IDetectedFace
    {
        DetectedFace(std::nullptr_t) noexcept {}
        DetectedFace(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::FaceAnalysis::IDetectedFace(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FaceDetector : winrt::Windows::Media::FaceAnalysis::IFaceDetector
    {
        FaceDetector(std::nullptr_t) noexcept {}
        FaceDetector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::FaceAnalysis::IFaceDetector(ptr, take_ownership_from_abi) {}
        static auto CreateAsync();
        static auto GetSupportedBitmapPixelFormats();
        static auto IsBitmapPixelFormatSupported(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& bitmapPixelFormat);
        [[nodiscard]] static auto IsSupported();
    };
    struct __declspec(empty_bases) FaceTracker : winrt::Windows::Media::FaceAnalysis::IFaceTracker
    {
        FaceTracker(std::nullptr_t) noexcept {}
        FaceTracker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::FaceAnalysis::IFaceTracker(ptr, take_ownership_from_abi) {}
        static auto CreateAsync();
        static auto GetSupportedBitmapPixelFormats();
        static auto IsBitmapPixelFormatSupported(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& bitmapPixelFormat);
        [[nodiscard]] static auto IsSupported();
    };
}
#endif
