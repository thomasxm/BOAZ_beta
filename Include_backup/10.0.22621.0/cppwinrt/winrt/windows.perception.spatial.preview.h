// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Perception_Spatial_Preview_H
#define WINRT_Windows_Perception_Spatial_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Perception.Spatial.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Perception.Spatial.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>::CoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview)->get_CoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>::NodeId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview)->get_NodeId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float4x4) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>::CoordinateSystemToNodeTransform() const
    {
        winrt::Windows::Foundation::Numerics::float4x4 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview)->get_CoordinateSystemToNodeTransform(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateCoordinateSystemForNode(winrt::guid const& nodeId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateCoordinateSystemForNode(impl::bind_in(nodeId), &result));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateCoordinateSystemForNode(winrt::guid const& nodeId, winrt::Windows::Foundation::Numerics::float3 const& relativePosition) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateCoordinateSystemForNodeWithPosition(impl::bind_in(nodeId), impl::bind_in(relativePosition), &result));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateCoordinateSystemForNode(winrt::guid const& nodeId, winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateCoordinateSystemForNodeWithPositionAndOrientation(impl::bind_in(nodeId), impl::bind_in(relativePosition), impl::bind_in(relativeOrientation), &result));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocator) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateLocatorForNode(winrt::guid const& nodeId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateLocatorForNode(impl::bind_in(nodeId), &result));
        return winrt::Windows::Perception::Spatial::SpatialLocator{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>::TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2)->TryCreateFrameOfReference(*(void**)(&coordinateSystem), &result));
        return winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>::TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& relativePosition) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2)->TryCreateFrameOfReferenceWithPosition(*(void**)(&coordinateSystem), impl::bind_in(relativePosition), &result));
        return winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview) consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>::TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2)->TryCreateFrameOfReferenceWithPositionAndOrientation(*(void**)(&coordinateSystem), impl::bind_in(relativePosition), impl::bind_in(relativeOrientation), &result));
        return winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> : produce_base<D, winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>
    {
        int32_t __stdcall get_CoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NodeId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().NodeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CoordinateSystemToNodeTransform(winrt::Windows::Foundation::Numerics::float4x4* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float4x4>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float4x4>(this->shim().CoordinateSystemToNodeTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> : produce_base<D, winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>
    {
        int32_t __stdcall CreateCoordinateSystemForNode(winrt::guid nodeId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CreateCoordinateSystemForNode(*reinterpret_cast<winrt::guid const*>(&nodeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCoordinateSystemForNodeWithPosition(winrt::guid nodeId, winrt::Windows::Foundation::Numerics::float3 relativePosition, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CreateCoordinateSystemForNode(*reinterpret_cast<winrt::guid const*>(&nodeId), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCoordinateSystemForNodeWithPositionAndOrientation(winrt::guid nodeId, winrt::Windows::Foundation::Numerics::float3 relativePosition, winrt::Windows::Foundation::Numerics::quaternion relativeOrientation, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CreateCoordinateSystemForNode(*reinterpret_cast<winrt::guid const*>(&nodeId), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateLocatorForNode(winrt::guid nodeId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::SpatialLocator>(this->shim().CreateLocatorForNode(*reinterpret_cast<winrt::guid const*>(&nodeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> : produce_base<D, winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>
    {
        int32_t __stdcall TryCreateFrameOfReference(void* coordinateSystem, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>(this->shim().TryCreateFrameOfReference(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFrameOfReferenceWithPosition(void* coordinateSystem, winrt::Windows::Foundation::Numerics::float3 relativePosition, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>(this->shim().TryCreateFrameOfReference(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFrameOfReferenceWithPositionAndOrientation(void* coordinateSystem, winrt::Windows::Foundation::Numerics::float3 relativePosition, winrt::Windows::Foundation::Numerics::quaternion relativeOrientation, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>(this->shim().TryCreateFrameOfReference(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview
{
    inline auto SpatialGraphInteropPreview::CreateCoordinateSystemForNode(winrt::guid const& nodeId)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics>([&](ISpatialGraphInteropPreviewStatics const& f) { return f.CreateCoordinateSystemForNode(nodeId); });
    }
    inline auto SpatialGraphInteropPreview::CreateCoordinateSystemForNode(winrt::guid const& nodeId, winrt::Windows::Foundation::Numerics::float3 const& relativePosition)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics>([&](ISpatialGraphInteropPreviewStatics const& f) { return f.CreateCoordinateSystemForNode(nodeId, relativePosition); });
    }
    inline auto SpatialGraphInteropPreview::CreateCoordinateSystemForNode(winrt::guid const& nodeId, winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics>([&](ISpatialGraphInteropPreviewStatics const& f) { return f.CreateCoordinateSystemForNode(nodeId, relativePosition, relativeOrientation); });
    }
    inline auto SpatialGraphInteropPreview::CreateLocatorForNode(winrt::guid const& nodeId)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics>([&](ISpatialGraphInteropPreviewStatics const& f) { return f.CreateLocatorForNode(nodeId); });
    }
    inline auto SpatialGraphInteropPreview::TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics2>([&](ISpatialGraphInteropPreviewStatics2 const& f) { return f.TryCreateFrameOfReference(coordinateSystem); });
    }
    inline auto SpatialGraphInteropPreview::TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& relativePosition)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics2>([&](ISpatialGraphInteropPreviewStatics2 const& f) { return f.TryCreateFrameOfReference(coordinateSystem, relativePosition); });
    }
    inline auto SpatialGraphInteropPreview::TryCreateFrameOfReference(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation)
    {
        return impl::call_factory<SpatialGraphInteropPreview, ISpatialGraphInteropPreviewStatics2>([&](ISpatialGraphInteropPreviewStatics2 const& f) { return f.TryCreateFrameOfReference(coordinateSystem, relativePosition, relativeOrientation); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
