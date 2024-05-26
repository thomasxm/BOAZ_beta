// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Perception_Spatial_Surfaces_2_H
#define WINRT_Windows_Perception_Spatial_Surfaces_2_H
#include "winrt/impl/Windows.Perception.Spatial.Surfaces.1.h"
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Surfaces
{
    struct __declspec(empty_bases) SpatialSurfaceInfo : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo
    {
        SpatialSurfaceInfo(std::nullptr_t) noexcept {}
        SpatialSurfaceInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialSurfaceMesh : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh
    {
        SpatialSurfaceMesh(std::nullptr_t) noexcept {}
        SpatialSurfaceMesh(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialSurfaceMeshBuffer : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer
    {
        SpatialSurfaceMeshBuffer(std::nullptr_t) noexcept {}
        SpatialSurfaceMeshBuffer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialSurfaceMeshOptions : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions
    {
        SpatialSurfaceMeshOptions(std::nullptr_t) noexcept {}
        SpatialSurfaceMeshOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions(ptr, take_ownership_from_abi) {}
        SpatialSurfaceMeshOptions();
        [[nodiscard]] static auto SupportedVertexPositionFormats();
        [[nodiscard]] static auto SupportedTriangleIndexFormats();
        [[nodiscard]] static auto SupportedVertexNormalFormats();
    };
    struct __declspec(empty_bases) SpatialSurfaceObserver : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver
    {
        SpatialSurfaceObserver(std::nullptr_t) noexcept {}
        SpatialSurfaceObserver(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver(ptr, take_ownership_from_abi) {}
        SpatialSurfaceObserver();
        static auto RequestAccessAsync();
        static auto IsSupported();
    };
}
#endif
